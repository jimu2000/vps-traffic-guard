#!/bin/bash
# ============================================================================
# vps_security_guard.sh — VPS 安全监控（防挖矿 / 持久化检测 / rootkit）
#
# 功能：
#   1. CPU / 进程异常检测：单个进程 CPU > 50% 持续 10 分钟、或 1 分钟
#      负载 > 2×核数持续 10 分钟，报警（疑似挖矿）
#   2. 挖矿连接检测：发现到矿池端口（3333/4444/5555/7777/14444 等）
#      的出站连接，报警
#   3. 持久化基线对比：crontab、/etc/cron.d、systemd 启用服务、
#      /root/.ssh/authorized_keys 发生变化，报警
#   4. rkhunter 检查：每周扫描 rootkit，有警告则报警
#
# 容器适配：LXC / Docker 等容器里 /proc/loadavg 反映的是宿主机负载
# （内核不隔离 loadavg），负载检查会自动跳过，避免误报。单进程 CPU
# 检查用 ps（容器内可见），不受影响。
#
# 用法：
#   vps_security_guard.sh            常规检查（CPU/挖矿连接/持久化），供 cron 每 10 分钟调用
#   vps_security_guard.sh --test     发送一条测试报警
#   vps_security_guard.sh --rkhunter 跑 rkhunter 检查并报警（供 cron 每周调用）
#
# 报警走加密 Bark 推送（AES-256-CBC，每次随机 IV），只有你的 Bark App
# 能解密内容。详见 README.md。
#
# 项目主页：https://github.com/jimu2000/vps-traffic-guard
# ============================================================================

# ============================================================================
# ★★★ 需要修改的配置（都在这里，改完就能用）★★★
# ============================================================================

# Bark 设备 Key
# 在 Bark App 里查看：打开 Bark App，设备 Key 就显示在首页（一串字母数字）。
# 把下面 xxxxxxxxx 换成你的设备 Key。
BARK_DEVICE_KEY="xxxxxxxxx"

# Bark 加密 Key 文件（32 位 Key，存放在这个文件里，不要写在脚本里）
# 生成方法：head -c 32 /dev/urandom | base64 | head -c 32 > /root/.bark_enc_key
#           chmod 600 /root/.bark_enc_key
# 并在 Bark App 里设置相同的 Key：设置 → 加密 → AES256 / CBC / pkcs7
BARK_ENC_KEY_FILE="/root/.bark_enc_key"

# Bark 服务器地址（自建 Bark 服务端才需要改，默认用官方服务器）
BARK_SERVER="https://api.day.app"

# ============================================================================
# 以下一般不用改
# ============================================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

STATE_DIR="/root/.security_guard"
BASELINE_DIR="/root/.security_baseline"
HOST_ID="$(hostname 2>/dev/null || echo unknown)"
# 公网 IP：推送里显示公网 IP 才能认出是哪台机器（内网 IP 10.0.0.x 认不出来）
# 优先 IPv4，失败时试 IPv6（纯 IPv6 机器），再失败回退本机 IP
HOST_IP="$(curl -4 -s --max-time 3 https://ip.sb 2>/dev/null)"
[ -z "$HOST_IP" ] && HOST_IP="$(curl -s --max-time 3 https://ip.sb 2>/dev/null)"
[ -z "$HOST_IP" ] && HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$HOST_IP" ] && HOST_IP="?"
mkdir -p "$STATE_DIR" "$BASELINE_DIR" 2>/dev/null

# ---------- 容器检测 ----------
# LXC/Docker 等容器里 /proc/loadavg 反映的是宿主机负载（内核不隔离 loadavg），
# 数值与本容器实际负载无关，负载检查在容器内无意义，必须跳过，否则持续误报。
# 单进程 CPU 检查用的是 ps（PID 命名空间隔离，容器内可见），不受影响。
IS_CONTAINER=0
if [ -f /.dockerenv ]; then
    IS_CONTAINER=1
elif command -v systemd-detect-virt >/dev/null 2>&1; then
    _virt=$(systemd-detect-virt 2>/dev/null || echo none)
    case "$_virt" in
        lxc|lxc-libvirt|docker|podman|openvz|systemd-nspawn) IS_CONTAINER=1 ;;
    esac
fi

# ---------- 内部变量 ----------
BARK_KEY="$BARK_DEVICE_KEY"
ENC_KEY_FILE="$BARK_ENC_KEY_FILE"

# ---------- 工具函数 ----------
json_safe() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | head -c 900; }

bark_enc() {
    local title body sound key iv key_hex iv_hex json ct resp
    title=$(json_safe "$1"); body=$(json_safe "$2"); sound="${3:-alarm}"
    if [ "$BARK_KEY" = "xxxxxxxxx" ] || [ -z "$BARK_KEY" ]; then
        echo "bark_enc: 请先在脚本顶部把 BARK_DEVICE_KEY 改成你的 Bark 设备 Key" >&2
        return 1
    fi
    [ -f "$ENC_KEY_FILE" ] || { echo "bark_enc: 找不到加密 Key 文件 $ENC_KEY_FILE" >&2; return 1; }
    key=$(cat "$ENC_KEY_FILE" 2>/dev/null) || return 1
    [ -n "$key" ] || return 1
    # 每次推送生成一个全新的随机 16 位 IV
    iv=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    key_hex=$(printf '%s' "$key" | od -An -tx1 -v | tr -d ' \n')
    iv_hex=$(printf '%s' "$iv" | od -An -tx1 -v | tr -d ' \n')
    json="{\"title\":\"$title\",\"body\":\"$body\",\"sound\":\"$sound\"}"
    ct=$(printf '%s' "$json" | openssl enc -aes-256-cbc -K "$key_hex" -iv "$iv_hex" 2>/dev/null | base64 -w 0) || return 1
    resp=$(curl -s --max-time 15 -X POST "$BARK_SERVER/$BARK_KEY/" --data-urlencode "ciphertext=$ct" --data-urlencode "iv=$iv" 2>&1)
    echo "$resp"
    case "$resp" in *'"code":200'*) return 0;; *) return 1;; esac
}

# 报警冷却：状态文件不存在或已超过冷却秒数 → 返回 0（可以报警）
should_alert() {
    local f="$STATE_DIR/$1" cooldown="${2:-43200}" now mtime age
    [ -f "$f" ] || return 0
    now=$(date +%s); mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    age=$((now - mtime))
    [ "$age" -ge "$cooldown" ]
}
mark_alerted() { touch "$STATE_DIR/$1"; }
clear_alerted() { rm -f "$STATE_DIR/$1"; }

log() { echo "$(date '+%F %T') $*"; }

# ---------- 检查 1：CPU / 进程异常（防挖矿） ----------
check_cpu() {
    local ncpu load1 top_pid top_name top_cpu suspect_file
    ncpu=$(nproc 2>/dev/null || echo 1)
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)

    top_pid=""; top_name=""; top_cpu=""
    while read -r pid comm cpu; do
        case "$comm" in
            xray|nginx|crowdsec|cscli|fail2ban-server|sshd|systemd|cron|vnstatd|r_client|wireguard-go|wg|unattended-upgr|apt|dpkg|ps|bash|sh|awk|grep|dockerd|containerd|docker-proxy|ss|sleep|curl|openssl|base64|od|tr|head|sort|find|sha256sum|systemctl|crontab|systemd-*|kworker*|ksoftirqd*|migration*|rcu*|watchdog*|kthreadd*|kdevtmpfs*)
                continue ;;
            *) top_pid="$pid"; top_name="$comm"; top_cpu="$cpu"; break ;;
        esac
    done < <(ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | tail -n +2 | head -10)

    suspect_file="$STATE_DIR/cpu_suspect"
    # 规则 A：单个非白名单进程 CPU > 50%，连续两次检查都存在 → 报警
    if [ -n "$top_cpu" ] && awk -v c="$top_cpu" 'BEGIN{exit !(c > 50)}'; then
        if [ -f "$suspect_file" ]; then
            local old_pid old_name
            read -r old_pid old_name < "$suspect_file" 2>/dev/null
            if [ "$old_pid" = "$top_pid" ] && [ "$old_name" = "$top_name" ]; then
                if should_alert "cpu_alerted" 43200; then
                    bark_enc "CPU 异常告警" "主机 $HOST_ID ($HOST_IP)：进程 $top_name (PID $top_pid) CPU 占用 $top_cpu%，已持续超过 10 分钟，疑似挖矿，请检查。" "alarm"
                    mark_alerted "cpu_alerted"
                    log "CPU 报警: $top_name PID $top_pid CPU $top_cpu%"
                fi
            fi
        else
            echo "$top_pid $top_name" > "$suspect_file"
        fi
    else
        rm -f "$suspect_file"
        if [ -f "$STATE_DIR/cpu_alerted" ]; then
            bark_enc "CPU 已恢复正常" "主机 $HOST_ID ($HOST_IP)：CPU 占用已恢复正常。" "minuet"
            clear_alerted "cpu_alerted"
            log "CPU 恢复通知已发送"
        fi
    fi

    # 规则 B：1 分钟负载 > 2×核数，连续两次 → 报警（多线程挖矿）
    # 容器内跳过：/proc/loadavg 是宿主机负载，无参考价值
    if [ "$IS_CONTAINER" -eq 1 ]; then
        rm -f "$STATE_DIR/load_suspect"
        clear_alerted "load_alerted"
    elif awk -v l="$load1" -v n="$ncpu" 'BEGIN{exit !(l > 2*n)}'; then
        if [ -f "$STATE_DIR/load_suspect" ]; then
            if should_alert "load_alerted" 43200; then
                bark_enc "系统负载异常" "主机 $HOST_ID ($HOST_IP)：1 分钟负载 $load1，CPU 核数 $ncpu，负载持续过高，疑似挖矿或异常进程，请检查。" "alarm"
                mark_alerted "load_alerted"
                log "负载报警: load $load1 / ncpu $ncpu"
            fi
        else
            touch "$STATE_DIR/load_suspect"
        fi
    else
        rm -f "$STATE_DIR/load_suspect"
        clear_alerted "load_alerted"
    fi
}

# ---------- 检查 2：挖矿连接 ----------
check_mining() {
    local ports="3333|3334|4444|5555|7777|9999|14433|14444|45700"
    local found sig sig_file
    found=$(ss -tnp state established 2>/dev/null | awk -v ports="$ports" '
        NR>1 {
            peer=$5; n=split(peer, parts, ":"); port=parts[n]
            if (port ~ "^(" ports ")$") {
                proc="(unknown)"
                if (index($0, "users:((\"") > 0) {
                    proc=substr($0, index($0, "users:((\"") + 9)
                    sub(/".*$/, "", proc)
                }
                print port, peer, proc
            }
        }')
    sig_file="$STATE_DIR/mining_sig"
    if [ -n "$found" ]; then
        sig=$(printf '%s' "$found" | sha256sum | cut -d' ' -f1)
        if [ ! -f "$sig_file" ] || [ "$(cat "$sig_file" 2>/dev/null)" != "$sig" ]; then
            local detail
            detail=$(printf '%s' "$found" | head -3 | tr '\n' ';' | head -c 400)
            bark_enc "疑似挖矿连接" "主机 $HOST_ID ($HOST_IP)：发现到矿池端口的出站连接：$detail，请检查。" "alarm"
            echo "$sig" > "$sig_file"
            mark_alerted "mining_alerted"
            log "挖矿连接报警: $detail"
        elif should_alert "mining_alerted" 86400; then
            local detail
            detail=$(printf '%s' "$found" | head -3 | tr '\n' ';' | head -c 400)
            bark_enc "疑似挖矿连接（持续）" "主机 $HOST_ID ($HOST_IP)：矿池连接仍在持续：$detail，请检查。" "alarm"
            mark_alerted "mining_alerted"
            log "挖矿连接提醒: $detail"
        fi
    else
        rm -f "$sig_file"
        clear_alerted "mining_alerted"
    fi
}

# ---------- 检查 3：持久化基线对比 ----------
# 返回：0=无变化，1=有变化，2=首次创建基线
baseline_check() {
    local name="$1" content="$2" f="$BASELINE_DIR/$1"
    if [ ! -f "$f" ]; then
        printf '%s\n' "$content" > "$f"
        log "基线已创建: $name"
        return 2
    fi
    if printf '%s\n' "$content" | diff -q "$f" - >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 已知良性的持久化内容（我们自己的工具）：返回 0=良性
is_known_good_text() {
    local text="$1"
    printf '%s' "$text" | grep -qiE \
        -e 'acme\.sh' \
        -e 'oracle_traffic_(guard|ultimate)\.py' \
        -e 'auto_limit\.sh' \
        -e 'vps_security_guard\.sh' \
        -e 'mail_forwarder\.py' \
        -e 'xray-auto-update\.sh' \
        -e 'nginx-auto-update\.sh' \
        -e 'rbot-clone' \
        -e 'r_client' \
        -e 'rkhunter' \
        -e 'unattended-upgrade' \
        -e 'vnstat' \
        -e 'certbot' \
        -e 'letsencrypt' \
        && return 0
    return 1
}

# 可疑特征：返回 0=可疑，1=无可疑特征
# 覆盖：临时目录/隐藏路径执行、下载即执行、编码执行、挖矿特征、编码命令。
is_suspicious_text() {
    local text="$1"
    printf '%s' "$text" | grep -qiE \
        -e '/tmp/' -e '/dev/shm' -e '/var/tmp' \
        -e 'curl[^|]*\|[[:space:]]*(sh|bash|dash)' \
        -e 'wget[^|]*\|[[:space:]]*(sh|bash|dash)' \
        -e 'base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(sh|bash)' \
        -e 'xmrig|minerd|cryptonight|monero|stratum\+tcp|nicehash' \
        -e ':(3333|4444|5555|7777|9000|14444|20580)\b' \
        -e 'eval[[:space:]]+\$\(' \
        -e 'python[0-9.]*[[:space:]]+-c[[:space:]]+["'"'"']' \
        -e 'perl[[:space:]]+-e[[:space:]]+["'"'"']' \
        -e 'nc[[:space:]]+-[el]+' \
        && return 0
    return 1
}

# 新增 systemd 服务：查它的 ExecStart 再判（只看服务名看不出跑什么）。
# 返回 0=可疑，1=良性。
check_new_service() {
    local unit="$1" exec_line unit_file
    exec_line=$(systemctl show "$unit" -p ExecStart -p ExecStartPre 2>/dev/null \
        | grep -v '^ExecStart=$' | grep -v '^ExecStartPre=$' | head -5)
    [ -z "$exec_line" ] && exec_line=$(systemctl cat "$unit" 2>/dev/null \
        | grep -E '^ExecStart' | head -5)
    # 单元文件不在常规目录（/etc 或 /lib 下的 systemd）→ 可疑
    unit_file=$(systemctl show "$unit" -p FragmentPath 2>/dev/null | cut -d= -f2)
    case "$unit_file" in
        /etc/systemd/system/*|/lib/systemd/system/*|/usr/lib/systemd/system/*) ;;
        *) [ -n "$unit_file" ] && return 0 ;;
    esac
    [ -z "$exec_line" ] && return 1
    is_known_good_text "$exec_line" && return 1
    is_suspicious_text "$exec_line"
}

check_persistence() {
    local changed="" rc sig sig_file
    local cron_content crond_content systemd_content auth_content
    local added="" removed="" detail="" suspicious=0
    local f new_units unit

    cron_content=$(crontab -l 2>/dev/null || echo "(no crontab)")
    baseline_check "crontab.txt" "$cron_content"; rc=$?
    [ "$rc" -eq 1 ] && changed="$changed crontab"
    crond_content=$(find /etc/cron.d -type f -exec sha256sum {} \; 2>/dev/null | sort)
    baseline_check "cron_d.txt" "$crond_content"; rc=$?
    [ "$rc" -eq 1 ] && changed="$changed cron.d"
    systemd_content=$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | sort)
    baseline_check "systemd.txt" "$systemd_content"; rc=$?
    [ "$rc" -eq 1 ] && changed="$changed systemd"
    auth_content=$(cat /root/.ssh/authorized_keys 2>/dev/null || echo "(no authorized_keys)")
    baseline_check "authorized_keys.txt" "$auth_content"; rc=$?
    [ "$rc" -eq 1 ] && changed="$changed authorized_keys"

    [ -z "$changed" ] && return 0

    # ---- 提取新增/删除行，逐项判定是否异常 ----
    case "$changed" in
        *crontab*)
            added=$(printf '%s\n' "$cron_content" \
                | diff "$BASELINE_DIR/crontab.txt" - 2>/dev/null | grep '^> ' | sed 's/^> //')
            removed=$(printf '%s\n' "$cron_content" \
                | diff "$BASELINE_DIR/crontab.txt" - 2>/dev/null | grep '^< ' | sed 's/^< //')
            detail="$detail[crontab 新增] $added "
            ;;
    esac
    case "$changed" in
        *cron.d*)
            # cron.d 基线是哈希列表：找出新增/变化的文件，读内容再判
            f=$(printf '%s\n' "$crond_content" \
                | diff "$BASELINE_DIR/cron_d.txt" - 2>/dev/null | grep '^> ' | awk '{print $3}')
            added="$added $(for x in $f; do [ -f "$x" ] && cat "$x"; done 2>/dev/null)"
            detail="$detail[cron.d 变化文件] $f $added "
            ;;
    esac
    case "$changed" in
        *systemd*)
            new_units=$(printf '%s\n' "$systemd_content" \
                | diff "$BASELINE_DIR/systemd.txt" - 2>/dev/null | grep '^> ' | awk '{print $1}')
            removed="$removed $(printf '%s\n' "$systemd_content" \
                | diff "$BASELINE_DIR/systemd.txt" - 2>/dev/null | grep '^< ' | awk '{print $1}')"
            detail="$detail[systemd 新增] $new_units "
            for unit in $new_units; do
                if check_new_service "$unit"; then
                    suspicious=1
                    detail="$detail[可疑服务 $unit] $(systemctl show "$unit" -p ExecStart 2>/dev/null | head -1) "
                fi
            done
            # 安全服务被移除 = 有人在关防御，直接判可疑
            printf '%s' "$removed" | grep -qiE 'crowdsec|fail2ban|ufw|security_guard|rkhunter' && suspicious=1
            ;;
    esac
    case "$changed" in
        *authorized_keys*)
            # 新 SSH 公钥一律判可疑（可能是后门），必须人工确认
            suspicious=1
            detail="$detail[authorized_keys 变化] 请核对新增公钥 "
            ;;
    esac
    # 新增的 cron 内容：先过白名单，再查可疑特征
    if [ -n "$added" ]; then
        if ! is_known_good_text "$added" && is_suspicious_text "$added"; then
            suspicious=1
        fi
    fi
    # 被删除的 cron 里有安全监控脚本 = 有人在关监控
    printf '%s' "$removed" | grep -qiE 'security_guard|rkhunter|fail2ban|crowdsec' && suspicious=1

    sig_file="$STATE_DIR/persist_sig"
    if [ "$suspicious" -eq 1 ]; then
        # 异常：推送报警，附上实际变化内容；同一变化只推一次，不每天重复
        sig=$(printf '%s' "$changed $detail" | sha256sum | cut -d' ' -f1)
        if [ ! -f "$sig_file" ] || [ "$(cat "$sig_file" 2>/dev/null)" != "$sig" ]; then
            detail=$(printf '%s' "$detail" | tr '\n' ' ' | head -c 400)
            bark_enc "可疑持久化变化" "主机 $HOST_ID ($HOST_IP)：发现可疑持久化变化（$changed），请检查是否被入侵。变化：$detail" "alarm"
            echo "$sig" > "$sig_file"
            log "持久化可疑变化报警:$changed $detail"
        else
            log "持久化可疑变化与上次相同，不重复报警:$changed"
        fi
    else
        # 良性变化（如自己装的新服务、新 cron）：自动采纳进基线，只记日志不推送
        printf '%s\n' "$cron_content" > "$BASELINE_DIR/crontab.txt"
        printf '%s\n' "$crond_content" > "$BASELINE_DIR/cron_d.txt"
        printf '%s\n' "$systemd_content" > "$BASELINE_DIR/systemd.txt"
        printf '%s\n' "$auth_content" > "$BASELINE_DIR/authorized_keys.txt"
        rm -f "$sig_file"
        echo "$(date '+%F %T') 自动采纳良性持久化变化:$changed $detail" >> "$STATE_DIR/persist_adopted.log"
        log "持久化良性变化已自动采纳:$changed"
    fi
}

# ---------- rkhunter 检查 ----------
run_rkhunter() {
    if ! command -v rkhunter >/dev/null 2>&1; then
        log "rkhunter 未安装，跳过"
        return 1
    fi
    local out warn_count sig sig_file
    out=$(rkhunter --check --skip-keypress --report-warnings-only 2>&1)
    warn_count=$(printf '%s' "$out" | grep -cE "Warning:" || true)
    warn_count=$(printf '%s' "$warn_count" | tr -d ' ')
    [ -z "$warn_count" ] && warn_count=0
    sig_file="$STATE_DIR/rkhunter_sig"
    if [ "$warn_count" -gt 0 ]; then
        sig=$(printf '%s' "$out" | sha256sum | cut -d' ' -f1)
        if [ ! -f "$sig_file" ] || [ "$(cat "$sig_file" 2>/dev/null)" != "$sig" ]; then
            local sample
            sample=$(printf '%s' "$out" | grep -i "Warning:" | head -5 | tr '\n' ';' | head -c 500)
            bark_enc "rkhunter 发现警告" "主机 $HOST_ID ($HOST_IP)：rkhunter 检查发现 $warn_count 条警告：$sample 详情见 /var/log/rkhunter.log" "alarm"
            echo "$sig" > "$sig_file"
            log "rkhunter 报警: $warn_count 条警告"
        else
            log "rkhunter: 警告与上次相同，不重复报警 ($warn_count 条)"
        fi
    else
        rm -f "$sig_file"
        log "rkhunter: 无警告"
    fi
}

# ---------- 主入口 ----------
case "${1:-}" in
    --test)
        log "发送测试报警..."
        resp=$(bark_enc "安全监控测试" "主机 $HOST_ID ($HOST_IP)：VPS 安全监控已部署，加密 Bark 测试报警。" "alarm")
        echo "Bark 返回: $resp"
        case "$resp" in *'"code":200'*) log "测试成功"; exit 0;; *) log "测试失败"; exit 1;; esac
        ;;
    --rkhunter)
        run_rkhunter
        ;;
    *)
        check_cpu
        check_mining
        check_persistence
        ;;
esac
