#!/usr/bin/env python3
"""
甲骨文云流量终极守卫（公开版）：
vnstat / ip -s link 双保险统计 + 公网IP与地理位置解析 + 阶梯预警 + 超限处理（二选一）

超限处理两种模式自由选择（改 OVER_LIMIT_MODE 一个数字）：
  0 = 阻断断网（iptables 熔断：切断外网出站，保留 SSH 逃生门）
  1 = 限速不断网（tc 限流：降到约 200KB/s，SSH 与服务都不掉线）

依赖：vnstat、python3、curl、iptables（阻断模式）、iproute2（限速模式）
推送：Bark 加密推送（AES-256-CBC，每次随机 IV），需在 Bark App 里设置加密 Key
"""
import sys
import os
import json
import base64
import secrets
import string
import subprocess
from datetime import datetime

# ==================== ★★★ 流量阈值配置（都在这里，改数字就能用）★★★ ====================
#
# 【超限处理模式】改这一个数字，决定流量超了之后怎么办：
OVER_LIMIT_MODE = 0        # 0 = 阻断断网（iptables 熔断，切断外网，SSH 逃生门保留）
                           # 1 = 限速不断网（tc 限流到 RATE_LIMIT，SSH 与服务都不掉线）
                           # 选 0 还是选 1：怕超额扣费选 0（最保险）；怕断网影响服务选 1（不断连）
#
# 【月流量硬顶】当月出站流量达到这个值，触发超限处理（按上面选的模式执行）
MONTHLY_LIMIT_GB = 200.0   # 单位 GB，甲骨文免费 tier 每月 10TB 出站，一般设 200 防失控
#
# 【限速速率】仅 OVER_LIMIT_MODE=1 时生效，超限后把网速降到这个值
RATE_LIMIT = "1600kbit"    # 约 200KB/s，够 SSH 操作、不够跑满流量；想更慢改 800kbit，更快改 5mbit
#
# 【阶梯预警】到量就推一条 Bark 提醒（每档每月只推一次，跨月自动重置）
# 格式：(阈值 GB, 提醒标题, 提示音)
STAGES = [
    (100.0, "100GB 阶段警报", "minuet"),
    (50.0,  "50GB 阶段提醒",  "telegraph"),
    (20.0,  "20GB 阶段提醒",  "chime"),
    (5.0,   "5GB 阶段提醒",   "glass"),
]
#
# 【SSH 逃生端口】自动识别 sshd 实际监听的端口，不用手动改
# 识别顺序：ss 监听端口 → sshd_config → 默认 22
# 如自动识别不准，取消下面一行的注释手动指定：
# SSH_PORT_OVERRIDE = 22
#
# 【Bark 推送】把 xxxxx 换成你自己的
#   BARK_KEY：Bark App 里设备 Key（22 位）
#   BARK_ENC_KEY：Bark App 加密设置里的 Key（32 位），与 App 里填的一致
#   BARK_SERVER：自建 Bark 服务端才改，默认官方 api.day.app
BARK_KEY = "xxxxxxxxx"
BARK_ENC_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
BARK_SERVER = "https://api.day.app"
# ==================== 配置结束，下面是程序逻辑，一般不用改 ====================

STATE_DIR = "/var/lib/oracle_traffic_guard"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_FILE = "/var/log/oracle_traffic_guard.log"


def log_msg(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] {msg}"
    print(formatted)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass


def run_cmd(cmd: str):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def get_active_iface() -> str:
    """网卡识别：默认路由优先 + 常见网卡兜底，覆盖各家云厂商"""
    rc, out, _ = run_cmd("ip route show default | awk '/default/ {print $5}' | head -n1")
    if rc == 0 and out:
        return out.strip()
    for cand in ["eth0", "ens3", "ens5", "ens4", "enp0s3", "enp1s0", "eno1",
                 "ens6", "enp0s6", "venet0", "eth1", "enP1s1"]:
        if os.path.exists(f"/sys/class/net/{cand}"):
            return cand
    return "eth0"


IFACE = get_active_iface()


def detect_ssh_port() -> int:
    """自动识别 sshd 实际监听的端口：ss → sshd_config → 默认 22"""
    # 方法 1：ss 看 sshd 实际监听端口（最准）
    rc, out, _ = run_cmd("ss -tlnp 2>/dev/null | awk '/sshd/ {print $4}' | head -n1")
    if rc == 0 and out:
        port = out.strip().rsplit(":", 1)[-1]
        if port.isdigit():
            return int(port)
    # 方法 2：sshd_config 里的 Port（去掉注释行）
    try:
        with open("/etc/ssh/sshd_config", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Port "):
                    port = line.split()[1]
                    if port.isdigit():
                        return int(port)
    except Exception:
        pass
    # 方法 3：默认 22
    return 22


# 手动指定优先（SSH_PORT_OVERRIDE），否则自动识别
try:
    SSH_PORT = SSH_PORT_OVERRIDE
except NameError:
    SSH_PORT = detect_ssh_port()


def get_ip_and_geo() -> tuple:
    ip_info = "获取失败"
    geo_result = "未知国家 (未知地区)"
    rc, out, _ = run_cmd("curl -s --max-time 3 https://ip.sb")
    if rc == 0 and out:
        ip_info = out.strip()
    rc, out, _ = run_cmd("curl -s --max-time 3 http://ip-api.com/json/?lang=zh-CN")
    if rc == 0 and out:
        try:
            data = json.loads(out)
            if data.get("status") == "success":
                country = data.get("country", "未知国家")
                city = data.get("city", "未知地区")
                geo_result = f"{country} ({city})"
        except Exception:
            pass
    return ip_info, geo_result


def send_bark_notification(title: str, body: str, sound: str = "alarm"):
    """Bark 加密推送：AES-256-CBC + 每次随机 IV，App 端自动解密显示"""
    if not BARK_KEY or BARK_KEY == "xxxxxxxxx":
        log_msg("Bark Key 未配置，跳过推送")
        return
    if not BARK_ENC_KEY or BARK_ENC_KEY == "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx":
        log_msg("Bark 加密 Key 未配置，跳过推送")
        return
    try:
        # IV 必须是 16 位 ASCII 字符串，发送时用原文（不要 base64），否则 App 解密失败收不到
        alphabet = string.ascii_letters + string.digits
        iv = "".join(secrets.choice(alphabet) for _ in range(16))
        payload = json.dumps({
            "title": title, "body": body, "sound": sound,
            "group": "VPS 流量卫士",
        }, ensure_ascii=False)
        p = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-K", BARK_ENC_KEY.encode().hex(),
             "-iv", iv.encode().hex()],
            input=payload.encode(), capture_output=True)
        if p.returncode != 0:
            log_msg(f"Bark 加密失败: {p.stderr.decode(errors='replace')}")
            return
        ciphertext = base64.b64encode(p.stdout).decode()
        url = f"{BARK_SERVER}/{BARK_KEY}/"
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", "-X", "POST", url,
             "--data-urlencode", f"ciphertext={ciphertext}",
             "--data-urlencode", f"iv={iv}"],
            capture_output=True, text=True)
        if r.returncode == 0:
            try:
                resp = json.loads(r.stdout)
                if resp.get("code") == 200:
                    log_msg(f"Bark 推送成功: {title}")
                else:
                    log_msg(f"Bark 推送返回异常: {r.stdout[:200]}")
            except Exception:
                log_msg(f"Bark 推送响应解析失败: {r.stdout[:200]}")
        else:
            log_msg(f"Bark 推送请求失败: {r.stderr[:200]}")
    except Exception as e:
        log_msg(f"发送 Bark 通知失败: {e}")


def get_ip_tx_bytes() -> int:
    rc, out, _ = run_cmd(f"ip -s link show {IFACE}")
    if rc == 0 and out:
        try:
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "TX:" in line and i + 1 < len(lines):
                    parts = lines[i + 1].strip().split()
                    if parts:
                        return int(parts[0])
        except Exception as e:
            log_msg(f"解析 ip -s link 出错: {e}")
    return 0


def get_monthly_tx_bytes() -> int:
    rc, out, _ = run_cmd(f"vnstat -i {IFACE} --json m")
    if rc == 0 and out:
        try:
            data = json.loads(out)
            for iface in data.get("interfaces", []):
                if iface.get("name") == IFACE:
                    now = datetime.now()
                    for m in iface.get("traffic", {}).get("month", []):
                        d = m.get("date", {})
                        if d.get("year") == now.year and d.get("month") == now.month:
                            val = m.get("tx", 0)
                            if val > 0:
                                return val
        except Exception as e:
            log_msg(f"解析 vnstat 出错: {e}")
    return get_ip_tx_bytes()


# ==================== 模式 0：阻断断网（iptables 熔断） ====================

def ensure_chain():
    run_cmd("iptables -N TRAFFIC_GUARD 2>/dev/null || true")
    rc, _, _ = run_cmd("iptables -C OUTPUT -j TRAFFIC_GUARD 2>/dev/null")
    if rc != 0:
        run_cmd("iptables -I OUTPUT 1 -j TRAFFIC_GUARD")


def is_circuit_broken() -> bool:
    rc, out, _ = run_cmd("iptables -L TRAFFIC_GUARD -n -v")
    return rc == 0 and "DROP" in out


def trip_circuit_breaker(reason: str):
    """阻断模式：切断外网出站，保留 SSH 逃生门与内网"""
    ensure_chain()
    ip_info, geo_result = get_ip_and_geo()
    log_msg(f"触发流量看门狗紧急熔断！网卡: {IFACE}，IP: {ip_info}，原因: {reason}")
    cmds = [
        "iptables -F TRAFFIC_GUARD",
        "iptables -A TRAFFIC_GUARD -o lo -j ACCEPT",
        "iptables -A TRAFFIC_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A TRAFFIC_GUARD -p tcp --sport {SSH_PORT} -j ACCEPT",
        "iptables -A TRAFFIC_GUARD -d 10.0.0.0/8 -j ACCEPT",
        "iptables -A TRAFFIC_GUARD -d 172.16.0.0/12 -j ACCEPT",
        "iptables -A TRAFFIC_GUARD -d 192.168.0.0/16 -j ACCEPT",
        f"iptables -A TRAFFIC_GUARD -o {IFACE} -j DROP",
    ]
    for c in cmds:
        run_cmd(c)
    body = (f"公网 IP: {ip_info} ({geo_result})\n监听网卡: {IFACE}\n"
            f"当月出站已达硬顶阈值\n状态: 外网已切断，SSH ({SSH_PORT}) 逃生门已保留")
    send_bark_notification("VPS 流量超限已熔断断网", body, sound="alarm")
    log_msg("熔断生效：外网出站已切断，自定义 SSH 端口保持正常。")


def reset_circuit_breaker():
    run_cmd("iptables -F TRAFFIC_GUARD")
    run_cmd("iptables -A TRAFFIC_GUARD -j RETURN")
    log_msg("已解除 iptables 熔断。")


# ==================== 模式 1：限速不断网（tc 限流） ====================

def is_rate_limited() -> bool:
    rc, out, _ = run_cmd(f"tc qdisc show dev {IFACE}")
    return rc == 0 and "tbf" in out


def apply_rate_limit(reason: str):
    """限速模式：把出站网速降到 RATE_LIMIT，SSH 与服务都不掉线"""
    ip_info, geo_result = get_ip_and_geo()
    log_msg(f"触发流量限速！网卡: {IFACE}，IP: {ip_info}，原因: {reason}")
    run_cmd(f"tc qdisc del dev {IFACE} root 2>/dev/null || true")
    rc, _, err = run_cmd(
        f"tc qdisc add dev {IFACE} root tbf rate {RATE_LIMIT} burst 32kbit latency 400ms")
    if rc != 0:
        log_msg(f"tc 限速失败: {err}")
        return
    body = (f"公网 IP: {ip_info} ({geo_result})\n监听网卡: {IFACE}\n"
            f"当月出站已达硬顶阈值\n状态: 已限速至 {RATE_LIMIT}，不断网，SSH 正常\n"
            f"恢复命令: tc qdisc del dev {IFACE} root")
    send_bark_notification("VPS 流量超限已限速", body, sound="alarm")
    log_msg(f"限速生效：出站已降到 {RATE_LIMIT}，不断网。")


def reset_rate_limit():
    run_cmd(f"tc qdisc del dev {IFACE} root 2>/dev/null || true")
    log_msg("已解除 tc 限速。")


# ==================== 主检查逻辑 ====================

def check_traffic():
    ensure_chain()
    monthly_tx_bytes = get_monthly_tx_bytes()
    monthly_tx_gb = monthly_tx_bytes / (1024 ** 3)
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            pass
    current_month_str = datetime.now().strftime("%Y-%m")
    if state.get("last_month") != current_month_str:
        state = {"last_month": current_month_str, "notified_stages": []}
    notified_stages = state.get("notified_stages", [])

    # 超限处理：按配置的模式执行（0=阻断，1=限速）
    if monthly_tx_gb >= MONTHLY_LIMIT_GB:
        if OVER_LIMIT_MODE == 0:
            if not is_circuit_broken():
                trip_circuit_breaker(
                    f"当月累计出站已达 {monthly_tx_gb:.2f} GB（硬顶阈值 {MONTHLY_LIMIT_GB} GB）")
        else:
            if not is_rate_limited():
                apply_rate_limit(
                    f"当月累计出站已达 {monthly_tx_gb:.2f} GB（硬顶阈值 {MONTHLY_LIMIT_GB} GB）")

    # 阶梯预警
    for limit_val, title_text, sound_type in STAGES:
        if monthly_tx_gb >= limit_val and limit_val not in notified_stages:
            ip_info, geo_result = get_ip_and_geo()
            log_msg(f"流量预警：IP {ip_info} 月出站已达 {monthly_tx_gb:.2f} GB (触发 {limit_val}GB 阶梯)")
            body_msg = (f"公网 IP: {ip_info} ({geo_result})\n网卡: {IFACE}\n"
                        f"当前月出站: {monthly_tx_gb:.2f} GB")
            send_bark_notification(f"VPS {title_text}", body_msg, sound=sound_type)
            notified_stages.append(limit_val)
            break

    state["notified_stages"] = notified_stages
    state["monthly_tx_gb"] = round(monthly_tx_gb, 3)
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def show_status():
    ip_info, geo_result = get_ip_and_geo()
    mode_name = "阻断断网 (iptables 熔断)" if OVER_LIMIT_MODE == 0 else f"限速不断网 (tc {RATE_LIMIT})"
    print("=== 流量看门狗状态 ===")
    print(f"公网 IP 地址: {ip_info} ({geo_result})")
    print(f"当前识别网卡: {IFACE}")
    print(f"当前统计出站流量: {get_monthly_tx_bytes() / (1024**3):.3f} GB")
    print(f"月流量硬顶: {MONTHLY_LIMIT_GB} GB")
    print(f"超限处理模式: {mode_name}")
    print(f"熔断器状态: {'已熔断断网' if is_circuit_broken() else '未熔断'}")
    print(f"限速状态: {'已限速 ' + RATE_LIMIT if is_rate_limited() else '未限速'}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "status":
        show_status()
    elif action == "test":
        print("正在获取 IP 与地理位置并发送测试推送...")
        ip_info, geo_result = get_ip_and_geo()
        current_flow = get_monthly_tx_bytes() / (1024**3)
        mode_name = "阻断断网" if OVER_LIMIT_MODE == 0 else "限速不断网"
        status_str = "已熔断断网" if is_circuit_broken() else (
            "已限速" if is_rate_limited() else "正常畅通")
        body_msg = (f"公网 IP: {ip_info} ({geo_result})\n网卡: {IFACE}\n"
                    f"当前出站流量: {current_flow:.3f} GB\n超限模式: {mode_name}\n"
                    f"状态: {status_str}\n提示: IP与地理位置连通性测试成功！")
        send_bark_notification("VPS 流量卫士运行状态", body_msg, sound="glass")
        print("测试通知已成功发送至手机！")
    elif action == "trip":
        # 手动触发超限处理（按配置的模式执行）
        if OVER_LIMIT_MODE == 0:
            trip_circuit_breaker("管理员命令行手动触发测试")
            print("已成功模拟触发熔断！")
        else:
            apply_rate_limit("管理员命令行手动触发测试")
            print("已成功模拟触发限速！")
    elif action == "reset":
        # 解除两种超限状态（熔断 + 限速都清掉）
        reset_circuit_breaker()
        reset_rate_limit()
        print("已解除熔断与限速状态。")
    else:
        check_traffic()
