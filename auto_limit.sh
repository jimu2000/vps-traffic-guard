#!/bin/bash
# ============================================================================
# auto_limit.sh — VPS 流量卫士（出站流量监控 + 超限处理）
#
# 工作原理：
#   每 10 分钟读取网卡出站流量（tx_bytes），达到阈值时推送 Bark 提醒，
#   超过超限阈值时按 OVER_LIMIT_MODE 执行（0=阻断断网，1=限速不断网）。
#
#   模式 0 阻断断网：iptables 熔断，切断外网出站，SSH 逃生门保留。
#   模式 1 限速不断网：tc 限流到 RATE_LIMIT，服务器只是变慢（默认 200 KB/s），
#   SSH 照常能连，不会把自己锁在外面。想恢复全速，删除限速规则即可：
#       tc qdisc del dev <网卡> root
#
#   网卡自动识别：优先从默认路由获取网卡名（最准确），失败时按下面
#   的常见网卡列表依次尝试，全部失败则退出不执行。
#
# 用法（加入 cron，每 10 分钟跑一次）：
#   */10 * * * * /bin/bash /root/auto_limit.sh
#
# 项目主页：https://github.com/jimu2000/vps-traffic-guard
# ============================================================================
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ============================================================================
# ★★★ 流量阈值配置（都在这里，改数字就能用）★★★
# ============================================================================

# 阶段提醒 1：出站流量达到多少 GB 时推送一次提醒（只提醒，不限速）
# 例：想 5GB 就提醒，把 10 改成 5
LIMIT_10GB=10

# 阶段提醒 2：出站流量达到多少 GB 时推送一次提醒（只提醒，不限速）
# 例：想 50GB 提醒，把 20 改成 50
LIMIT_20GB=20

# 限速阈值：出站流量达到多少 GB 时自动限速（推送报警 + tc 限速）
LIMIT_GB=200

# 限速目标：触发限速后网卡出站速度（1600kbit ≈ 200 KB/s）
# 例：想限到 1Mbps，改成 "1mbit"；想限到 100KB/s，改成 "800kbit"
RATE_LIMIT="1600kbit"

# 超限处理模式：流量达到 LIMIT_GB 后怎么办（改一个数字就行）
#   0 = 阻断断网（iptables 熔断：切断外网出站，SSH 逃生门保留，怕扣费选这个）
#   1 = 限速不断网（tc 限流到 RATE_LIMIT，SSH 与服务都不掉线，怕断网选这个）
OVER_LIMIT_MODE=1

# SSH 逃生端口：自动识别 sshd 实际监听的端口，不用手动改
# 识别顺序：ss 监听端口 → sshd_config → 默认 22
# 如自动识别不准，取消下面一行的注释手动指定：
# SSH_PORT_OVERRIDE=22

# ============================================================================
# ★★★ Bark 推送配置 ★★★
# ============================================================================

# Bark 设备 Key（在 Bark App 首页查看，把 xxxxxxxxx 换成你的）
BARK_KEY="xxxxxxxxx"

# Bark 加密 Key 文件（32 位 Key，须与 Bark App 里设置的 Key 一致）
BARK_ENC_KEY_FILE="/root/.bark_enc_key"

# Bark 服务器地址（自建 Bark 服务端才需要改）
BARK_SERVER="https://api.day.app"

# ============================================================================
# 以下一般不用改
# ============================================================================
LOG_FILE="/var/log/traffic_limit.log"
STATE_FILE="/var/log/traffic_notified.state"

# Bark 加密推送：AES-256-CBC，每次随机 IV
bark_enc() {
    local _title="$1" _body="$2" _sound="$3"
    local _key _iv _key_hex _iv_hex _json _ct
    if [ "$BARK_KEY" = "xxxxxxxxx" ] || [ -z "$BARK_KEY" ]; then
        echo "bark_enc: 请先在脚本顶部把 BARK_KEY 改成你的 Bark 设备 Key" >&2
        return 1
    fi
    [ -f "$BARK_ENC_KEY_FILE" ] || return 1
    _key=$(cat "$BARK_ENC_KEY_FILE") || return 1
    [ -n "$_key" ] || return 1
    # 每次推送生成一个全新的随机 16 位 IV
    _iv=$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
    [ ${#_iv} -eq 16 ] || return 1
    _key_hex=$(printf '%s' "$_key" | od -An -tx1 -v | tr -d ' \n')
    _iv_hex=$(printf '%s' "$_iv" | od -An -tx1 -v | tr -d ' \n')
    _json=$(python3 -c 'import json,sys; print(json.dumps({"title":sys.argv[1],"body":sys.argv[2],"sound":sys.argv[3]}, ensure_ascii=False))' "$_title" "$_body" "$_sound") || return 1
    _ct=$(printf '%s' "$_json" | openssl enc -aes-256-cbc -K "$_key_hex" -iv "$_iv_hex" | base64 -w 0) || return 1
    curl -s --max-time 10 -X POST "$BARK_SERVER/$BARK_KEY/" --data-urlencode "ciphertext=$_ct" --data-urlencode "iv=$_iv" > /dev/null 2>&1
}

# ---------- 阻断模式（iptables 熔断，仅 OVER_LIMIT_MODE=0 时用） ----------
ensure_chain() {
    iptables -N TRAFFIC_GUARD 2>/dev/null || true
    if ! iptables -C OUTPUT -j TRAFFIC_GUARD 2>/dev/null; then
        iptables -I OUTPUT 1 -j TRAFFIC_GUARD
    fi
}

is_circuit_broken() {
    iptables -L TRAFFIC_GUARD -n -v 2>/dev/null | grep -q "DROP"
}

trip_circuit_breaker() {
    ensure_chain
    iptables -F TRAFFIC_GUARD
    iptables -A TRAFFIC_GUARD -o lo -j ACCEPT
    iptables -A TRAFFIC_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A TRAFFIC_GUARD -p tcp --sport "$SSH_PORT" -j ACCEPT
    iptables -A TRAFFIC_GUARD -d 10.0.0.0/8 -j ACCEPT
    iptables -A TRAFFIC_GUARD -d 172.16.0.0/12 -j ACCEPT
    iptables -A TRAFFIC_GUARD -d 192.168.0.0/16 -j ACCEPT
    iptables -A TRAFFIC_GUARD -o "$INTERFACE" -j DROP
}

# ---------- SSH 端口自动识别 ----------
# 熔断时要放行 SSH 端口，填错了阻断后连不上，所以自动检测 sshd 实际监听的端口
detect_ssh_port() {
    local _port
    # 方法 1：ss 看 sshd 实际监听端口（最准）
    _port=$(ss -tlnp 2>/dev/null | awk '/sshd/ {print $4}' | head -n1 | sed 's/.*://')
    if [ -n "$_port" ] && [ "$_port" -gt 0 ] 2>/dev/null; then
        echo "$_port"
        return
    fi
    # 方法 2：sshd_config 里的 Port（去掉注释行）
    _port=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1)
    if [ -n "$_port" ] && [ "$_port" -gt 0 ] 2>/dev/null; then
        echo "$_port"
        return
    fi
    # 方法 3：默认 22
    echo "22"
}

# 手动指定优先（SSH_PORT_OVERRIDE），否则自动识别
if [ -n "$SSH_PORT_OVERRIDE" ]; then
    SSH_PORT="$SSH_PORT_OVERRIDE"
else
    SSH_PORT=$(detect_ssh_port)
fi

# ---------- 网卡自动识别 ----------
# 优先从默认路由获取（最准确），失败时按常见网卡名依次尝试
INTERFACE=$(ip route show default 2>/dev/null | awk "/default/ {print \$5}" | head -n1)
if [ -z "$INTERFACE" ] || [ ! -f "/sys/class/net/$INTERFACE/statistics/tx_bytes" ]; then
    # 各云厂商常见网卡名（按通用程度排序）：
    #   eth0    — AWS(Xen)/Azure/DigitalOcean/IBM/Alibaba/Akamai(Linode)/OVH/Vultr/
    #             Hetzner/Huawei/Exoscale/Scaleway/Gcore/Contabo/Tencent/IONOS
    #   ens3    — Oracle Cloud/OVH/Vultr/Hetzner Cloud/Huawei/Exoscale/
    #             Scaleway/Gcore/Contabo/IONOS（KVM 云主机常见）
    #   ens5    — AWS Nitro(ENA)/Alibaba 新机型/Tencent 新机型
    #   ens4    — Google Cloud
    #   enp0s3  — Oracle 部分机型/KVM 通用
    #   enp1s0  — Vultr 新机型/Hetzner 独服/Scaleway
    #   eno1    — OVH 独服/Hetzner 独服
    #   ens6    — AWS 部分 Nitro 机型
    #   venet0  — OpenVZ 容器（Contabo 老款等）
    #   eth1    — 各厂商私网/内网网卡（备用）
    #   enP1s1  — Azure 部分可预测命名
    # 注：Backblaze B2 是纯对象存储，没有服务器/网卡，不适用本脚本。
    for _nic in eth0 ens3 ens5 ens4 enp0s3 enp1s0 eno1 ens6 venet0 eth1 enP1s1; do
        if [ -f "/sys/class/net/$_nic/statistics/tx_bytes" ]; then
            INTERFACE="$_nic"
            break
        fi
    done
fi
if [ -z "$INTERFACE" ] || [ ! -f "/sys/class/net/$INTERFACE/statistics/tx_bytes" ]; then
    echo "$(date): 无法识别网卡，退出" >> "$LOG_FILE"
    exit 1
fi

STAT_FILE="/sys/class/net/$INTERFACE/statistics/tx_bytes"
if [ -f "$STAT_FILE" ]; then
    TX_BYTES=$(cat "$STAT_FILE")
    TX_GB=$(awk "BEGIN {print $TX_BYTES / 1024 / 1024 / 1024}")
    TX_FORMATTED=$(awk "BEGIN {gb=$TX_GB; if(gb>=1) printf \"%.2f GB\", gb; else printf \"%.2f MB\", $TX_BYTES/1024/1024}")

    # --- 重启检测：流量计数器（tx_bytes）重启后清零，但状态文件还在 ---
    # 状态文件现在存两行：第 1 行是已提醒的阶段，第 2 行是开机时间
    # （/proc/stat 里的 btime，重启后会变）。开机时间变了就说明重启过，
    # 提醒阶段清零，否则流量重新涨到 10GB/20GB 时不会再提醒。
    BOOT_TIME=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
    NOTIFIED_STAGE=0
    SAVED_BOOT=""
    if [ -f "$STATE_FILE" ]; then
        NOTIFIED_STAGE=$(head -n1 "$STATE_FILE")
        SAVED_BOOT=$(sed -n '2p' "$STATE_FILE")
    fi
    [ "$NOTIFIED_STAGE" -ge 0 ] 2>/dev/null || NOTIFIED_STAGE=0
    if [ -z "$SAVED_BOOT" ]; then
        # 老格式状态文件（只有一行数字）：只补记当前开机时间，不重置阶段，
        # 避免升级后把已提醒过的阶段再推一次；之后重启就能正常识别了
        [ -n "$BOOT_TIME" ] && printf '%s\n%s\n' "$NOTIFIED_STAGE" "$BOOT_TIME" > "$STATE_FILE"
    elif [ -n "$BOOT_TIME" ] && [ "$SAVED_BOOT" != "$BOOT_TIME" ]; then
        echo "$(date): 检测到重启（开机时间 $SAVED_BOOT -> $BOOT_TIME），已清空阶段提醒状态" >> "$LOG_FILE"
        NOTIFIED_STAGE=0
        printf '%s\n%s\n' "0" "$BOOT_TIME" > "$STATE_FILE"
    fi
    
    IP_INFO=$(curl -s --max-time 5 https://ip.sb)
    [ -z "$IP_INFO" ] && IP_INFO="获取失败"
    
    GEO_RESULT="未知国家 (未知地区)"
    API_RES=$(curl -s --max-time 3 "http://ip-api.com/json/?lang=zh-CN")
    if [ -n "$API_RES" ]; then
        C_NAME=$(echo "$API_RES" | grep -o '"country":"[^"]*"' | head -n1 | cut -d'"' -f4)
        CI_NAME=$(echo "$API_RES" | grep -o '"city":"[^"]*"' | head -n1 | cut -d'"' -f4)
        [ -n "$C_NAME" ] && [ -n "$CI_NAME" ] && GEO_RESULT="$C_NAME ($CI_NAME)"
    fi

    # --- 1. 检查是否达到超限阈值（按 OVER_LIMIT_MODE 执行：0=阻断，1=限速）---
    if (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_GB) ? 1 : 0}") )); then
        if [ "$OVER_LIMIT_MODE" = "0" ]; then
            # 模式 0：阻断断网（iptables 熔断，切断外网，SSH 逃生门保留）
            if ! is_circuit_broken; then
                trip_circuit_breaker

                TITLE="🚨 VPS 流量超限警告 (已熔断断网)"
                BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 外网已切断，SSH ($SSH_PORT) 逃生门已保留"

                echo "$(date): 累计出站流量已达 $TX_FORMATTED，网卡 $INTERFACE 已熔断断网. IP: $IP_INFO ($GEO_RESULT)" >> "$LOG_FILE"

                bark_enc "$TITLE" "$BODY" "alarm"
            fi
        else
            # 模式 1：限速不断网（tc 限流，SSH 与服务都不掉线）
            if ! tc qdisc show dev "$INTERFACE" | grep -q "htb"; then
                tc qdisc del dev "$INTERFACE" root 2>/dev/null
                tc qdisc add dev "$INTERFACE" root handle 1: htb default 10
                tc class add dev "$INTERFACE" parent 1: classid 1:1 htb rate $RATE_LIMIT ceil $RATE_LIMIT
                tc class add dev "$INTERFACE" parent 1:1 classid 1:10 htb rate $RATE_LIMIT ceil $RATE_LIMIT
                tc filter add dev "$INTERFACE" protocol ip prio 1 u32 match u32 0 0 flowid 1:10

                TITLE="🚨 VPS 流量超限警告 (已限速)"
                BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 已强制限速至 $RATE_LIMIT"

                echo "$(date): 累计出站流量已达 $TX_FORMATTED，网卡 $INTERFACE 已强制限速. IP: $IP_INFO ($GEO_RESULT)" >> "$LOG_FILE"

                bark_enc "$TITLE" "$BODY" "alarm"
            fi
        fi
        
    # --- 2. 检查阶段提醒 2（阈值跟顶部 LIMIT_20GB 走）---
    elif (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_20GB) ? 1 : 0}") )) && [ "$NOTIFIED_STAGE" -lt "$LIMIT_20GB" ]; then
        TITLE="⚠️ VPS 流量阶段提醒 (${LIMIT_20GB}GB)"
        BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 流量已满 ${LIMIT_20GB}GB"
        
        echo "$(date): 流量已达 ${LIMIT_20GB} GB 阶段。当前: $TX_FORMATTED" >> "$LOG_FILE"
        printf '%s\n%s\n' "$LIMIT_20GB" "$BOOT_TIME" > "$STATE_FILE"
        
        bark_enc "$TITLE" "$BODY" "minuet"

    # --- 3. 检查阶段提醒 1（阈值跟顶部 LIMIT_10GB 走）---
    elif (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_10GB) ? 1 : 0}") )) && [ "$NOTIFIED_STAGE" -lt "$LIMIT_10GB" ]; then
        TITLE="ℹ️ VPS 流量阶段提醒 (${LIMIT_10GB}GB)"
        BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 流量已满 ${LIMIT_10GB}GB"
        
        echo "$(date): 流量已达 ${LIMIT_10GB} GB 阶段。当前: $TX_FORMATTED" >> "$LOG_FILE"
        printf '%s\n%s\n' "$LIMIT_10GB" "$BOOT_TIME" > "$STATE_FILE"
        
        bark_enc "$TITLE" "$BODY" "telegraph"
    fi
fi
