#!/bin/bash
# ============================================================================
# auto_limit.sh — VPS 流量卫士（出站流量监控 + 超限自动限速）
#
# 工作原理：
#   每 10 分钟读取网卡出站流量（tx_bytes），达到阈值时推送 Bark 提醒，
#   超过限速阈值时用 tc 把网卡限速到指定值。
#
#   ⚠️ 限速 ≠ 断网：触发限速后，服务器只是变慢（默认 200 KB/s），
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

    NOTIFIED_STAGE=0
    [ -f "$STATE_FILE" ] && NOTIFIED_STAGE=$(cat "$STATE_FILE")
    
    IP_INFO=$(curl -s --max-time 5 https://ip.sb)
    [ -z "$IP_INFO" ] && IP_INFO="获取失败"
    
    GEO_RESULT="未知国家 (未知地区)"
    API_RES=$(curl -s --max-time 3 "http://ip-api.com/json/?lang=zh-CN")
    if [ -n "$API_RES" ]; then
        C_NAME=$(echo "$API_RES" | grep -o '"country":"[^"]*"' | head -n1 | cut -d'"' -f4)
        CI_NAME=$(echo "$API_RES" | grep -o '"city":"[^"]*"' | head -n1 | cut -d'"' -f4)
        [ -n "$C_NAME" ] && [ -n "$CI_NAME" ] && GEO_RESULT="$C_NAME ($CI_NAME)"
    fi

    # --- 1. 检查是否达到限速阈值（限速 + 推送报警）---
    if (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_GB) ? 1 : 0}") )); then
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
        
    # --- 2. 检查阶段提醒 2（阈值跟顶部 LIMIT_20GB 走）---
    elif (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_20GB) ? 1 : 0}") )) && [ "$NOTIFIED_STAGE" -lt "$LIMIT_20GB" ]; then
        TITLE="⚠️ VPS 流量阶段提醒 (${LIMIT_20GB}GB)"
        BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 流量已满 ${LIMIT_20GB}GB"
        
        echo "$(date): 流量已达 ${LIMIT_20GB} GB 阶段。当前: $TX_FORMATTED" >> "$LOG_FILE"
        echo "$LIMIT_20GB" > "$STATE_FILE"
        
        bark_enc "$TITLE" "$BODY" "minuet"

    # --- 3. 检查阶段提醒 1（阈值跟顶部 LIMIT_10GB 走）---
    elif (( $(awk "BEGIN {print ($TX_GB >= $LIMIT_10GB) ? 1 : 0}") )) && [ "$NOTIFIED_STAGE" -lt "$LIMIT_10GB" ]; then
        TITLE="ℹ️ VPS 流量阶段提醒 (${LIMIT_10GB}GB)"
        BODY="网卡: $INTERFACE\n公网 IP: $IP_INFO ($GEO_RESULT)\n当前出站流量: $TX_FORMATTED\n状态: 流量已满 ${LIMIT_10GB}GB"
        
        echo "$(date): 流量已达 ${LIMIT_10GB} GB 阶段。当前: $TX_FORMATTED" >> "$LOG_FILE"
        echo "$LIMIT_10GB" > "$STATE_FILE"
        
        bark_enc "$TITLE" "$BODY" "telegraph"
    fi
fi
