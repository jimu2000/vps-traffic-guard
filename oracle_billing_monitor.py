#!/usr/bin/env python3
"""Oracle Cloud billing monitor — daily cost check + auto-stop paid instances.

What it does (run once a day via cron):
- For each configured tenancy, checks month-to-date cost vs your budget
  (default SGD 1.00) using the OCI Usage API.
- Detects new charges since the last run (state file).
- Lists instances in all subscribed regions; STOPs any RUNNING instance
  whose shape is never Always Free (E5/E4/E3/etc). Never touches
  A1.Flex / E2.1.Micro or the servers listed in NEVER_STOP_NAMES.
  (STOP, not terminate — you can start them again.)
- Flags Always Free allowance overruns (A1 > 4 OCPU / 24 GB, E2 micro > 2).

When there are alerts or errors, sends an encrypted Bark push
(AES-256-CBC, same method as bark_enc.sh in this repo).
Outputs a JSON report on stdout. Exit 0 on success, 1 if any account
check failed (API error).

Setup:
  1. pip install oci
  2. Create an OCI API key pair and add the public key to your tenancy
     (User Settings -> API Keys). Then either paste your API config
     into the OCI_CONFIG block at the top of this script (supports
     multiple profiles), or write ~/.oci/config with one profile per
     tenancy. See:
     https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm
  3. Edit the config section at the top: ACCOUNTS (profiles), BUDGET_SGD,
     NEVER_STOP_NAMES, and BARK_KEY / BARK_ENC_KEY for push alerts.
     Without Bark keys the script still runs and prints the report,
     just without push alerts.
  4. Add to cron, e.g. every morning at 08:15:
     15 8 * * * /usr/bin/python3 /path/to/oracle_billing_monitor.py

Config lives in the section below — edit it before first use.
"""
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import oci

# ============================================================================
# ★★★ 配置（使用前按你的账号修改）★★★
# 所有要改的东西都在这里，改完就能用。
# ============================================================================

# ==================== OCI API 配置 ====================
# 在 oci=begin 和 oci=end 之间放入你的 API 配置信息，支持多个配置文件。
# 格式和 ~/.oci/config 完全一样，每个 [段名] 是一个账号。
# 想换账号操作时，改下面 ACCOUNTS 里的 profile 名即可。
# 留空或保持占位符时，脚本改用 ~/.oci/config 文件里的配置。
OCI_CONFIG = """
oci=begin
[DEFAULT]
user=ocid1.user.oc1..xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
fingerprint=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
tenancy=ocid1.tenancy.oc1..xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
region=us-sanjose-1
key_file=/root/oci_api_key.pem
# 再加账号就照着上面复制一段，改段名即可：
# [ACCOUNT2]
# user=ocid1.user.oc1..yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
# fingerprint=yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy
# tenancy=ocid1.tenancy.oc1..yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
# region=ap-singapore-1
# key_file=/root/oci_api_key2.pem
oci=end
"""

# OCI 配置文件路径（上面 OCI_CONFIG 留空/占位符时才用，一般不用改）。
# 里面放的是 API 密钥、租户 OCID、指纹等，格式见脚本开头 docstring 里的官方文档链接。
CONFIG_FILE = os.path.expanduser("~/.oci/config")

# --- 账单与预算 ---
# 每月预算。超过即报警。按你的需要改。
# 注意单位要和下面的 CURRENCY 一致（新加坡账号一般是 SGD，美国账号一般是 USD）。
BUDGET_SGD = 1.00

# 账单货币：新加坡账号填 "SGD"，美国账号填 "USD"，其他地区按你的账单货币填。
# 报警消息里的金额单位都用这个。
CURRENCY = "SGD"

# 费用新增多少才报警（单位同上）。本月费用比上次检查新增超过这个数就推送。
# 例：想有任何新增就报警，改成 0；想只在新增超过 1 元时报警，改成 1。
DELTA_THRESHOLD = 0.01

# --- 要监控的账号 ---
# 每项对应上面 OCI_CONFIG 或 ~/.oci/config 里的一个 profile（[段名]）。
# name 只用于报告显示，随便起。
# 只有一个账号就删掉第二项；更多账号就照着加。
ACCOUNTS = [
    {"profile": "DEFAULT", "name": "my-tenancy-1"},
    # {"profile": "ACCOUNT2", "name": "my-tenancy-2"},
]

# --- 自动停机保护 ---
# 永不自动停机的实例显示名（display name）。即使某天分类逻辑误判，
# 这些实例也不会被停。把你重要的服务器名填进来。
NEVER_STOP_NAMES = {
    "my-important-server-1",
    "my-important-server-2",
}

# Always Free 规格（永不自动停机）。Oracle 如果新增免费规格，把名字加进来。
FREE_SHAPES = {"VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"}

# Always Free 额度上限（超出部分会收费）。Oracle 如果调整免费额度，按新标准改。
A1_OCPU_LIMIT = 4    # A1.Flex 免费 OCPU 上限
A1_MEM_LIMIT = 24    # A1.Flex 免费内存上限（GB）
E2_COUNT_LIMIT = 2   # E2.1.Micro 免费台数上限

# --- Bark 推送（报警发到手机）---
# Bark 设备 Key：Bark App 首页显示的那串，把 xxxxxxxxx 换成你的。
BARK_KEY = "xxxxxxxxx"

# Bark 加密 Key：32 位，必须和 Bark App 加密设置里的 Key 一致。
# 没开 Bark 加密时留空字符串 "" 也可以，但推送就是明文的了。
BARK_ENC_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Bark 服务器地址：自建 Bark 服务端才改，默认官方服务器。
BARK_SERVER = "https://api.day.app"

# Bark 推送的标题和分组名。想在手机上区分不同脚本的推送，改这里。
BARK_TITLE = "Oracle 账单预警"
BARK_GROUP = "oracle-billing"

# --- 文件保存位置 ---
# 状态文件与库存报告的保存目录：默认脚本所在目录。
# 也可用环境变量 ORACLE_BILLING_DIR 覆盖。
BASE = os.environ.get(
    "ORACLE_BILLING_DIR",
    os.path.dirname(os.path.abspath(__file__)),
)

# 备用：BARK_KEY 仍是占位符时，改读这两个外部文件（与脚本同目录，chmod 600）。
# 两个文件分别是 Bark 推送 URL 全串和 32 位加密 Key。两种方式填一种就行。
BARK_URL_FILE = os.path.join(BASE, "bark_url")
BARK_KEY_FILE = os.path.join(BASE, "bark_key")

# ============================================================================
# 以下不用改（由上面配置推导出来）
# ============================================================================

STATE_FILE = os.path.join(BASE, "state.json")
INVENTORY_FILE = os.path.join(BASE, "inventory.json")


def _is_placeholder(value):
    """True if a config value still looks like a placeholder."""
    return not value or "xxxx" in str(value).lower()


def load_oci_config(profile):
    """Load OCI config for a profile.
    Priority: inline OCI_CONFIG block > ~/.oci/config file.
    Returns a dict suitable for OCI SDK clients."""
    import configparser

    text = OCI_CONFIG.strip()
    lines = [
        ln for ln in text.splitlines()
        if ln.strip() not in ("oci=begin", "oci=end")
    ]
    # 注意：configparser 默认把 [DEFAULT] 当特殊段（默认值段），
    # 必须改 default_section，[DEFAULT] 才能当普通 profile 解析。
    parser = configparser.ConfigParser(
        default_section="__oci_no_defaults__", interpolation=None
    )
    try:
        parser.read_string("\n".join(lines))
    except configparser.Error:
        parser = None
    if parser is not None and parser.has_section(profile):
        cfg = dict(parser[profile])
        if not _is_placeholder(cfg.get("user", "")) and not _is_placeholder(
            cfg.get("fingerprint", "")
        ):
            return cfg
    return oci.config.from_file(CONFIG_FILE, profile)


def send_bark(title, body):
    """Send an encrypted Bark push (AES-256-CBC). Returns (ok, error).
    Priority: inline BARK_KEY / BARK_ENC_KEY > bark_url / bark_key files.
    Never logs the URL/key."""
    import base64
    import secrets
    import string
    import subprocess

    url = None
    enc_key = None
    if not _is_placeholder(BARK_KEY):
        url = f"{BARK_SERVER.rstrip('/')}/{BARK_KEY}/"
        enc_key = BARK_ENC_KEY
    if url is None or _is_placeholder(enc_key):
        try:
            with open(BARK_URL_FILE) as f:
                url = f.read().strip()
            with open(BARK_KEY_FILE) as f:
                enc_key = f.read().strip()
        except FileNotFoundError:
            return False, "bark url/key not configured"
    if not url or _is_placeholder(enc_key):
        return False, "bark url/key not configured"
    alphabet = string.ascii_letters + string.digits
    iv = "".join(secrets.choice(alphabet) for _ in range(16))
    payload = json.dumps(
        {"title": title, "body": body, "level": "active", "group": BARK_GROUP},
        ensure_ascii=False,
    )
    try:
        enc = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-K", enc_key.encode().hex(), "-iv", iv.encode().hex()],
            input=payload.encode("utf-8"), capture_output=True, timeout=15)
        if enc.returncode != 0:
            return False, "openssl encrypt failed"
        ct = base64.b64encode(enc.stdout).decode("ascii")
        data = urllib.parse.urlencode({"ciphertext": ct, "iv": iv}).encode("ascii")
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return False, str(e)
    if result.get("code") == 200:
        return True, ""
    return False, f"bark code={result.get('code')} message={result.get('message')}"


def month_bounds(now):
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if now.month == 12:
        end = start.replace(year=now.year + 1, month=1)
    else:
        end = start.replace(month=now.month + 1)
    return start, end


def get_mtd_cost(usage_client, tenancy_id, start, end):
    details = oci.usage_api.models.RequestSummarizedUsagesDetails(
        tenant_id=tenancy_id,
        time_usage_started=start,
        time_usage_ended=end,
        granularity="MONTHLY",
        query_type="COST",
    )
    resp = usage_client.request_summarized_usages(details)
    total = 0.0
    currency = CURRENCY
    for item in resp.data.items or []:
        total += item.computed_amount or 0.0
        currency = item.currency or currency
    return total, currency


def check_account(acct, now):
    profile = acct["profile"]
    config = load_oci_config(profile)
    tenancy_id = config["tenancy"]
    identity = oci.identity.IdentityClient(config)
    usage = oci.usage_api.UsageapiClient(config)

    start, end = month_bounds(now)
    mtd_cost, currency = get_mtd_cost(usage, tenancy_id, start, end)

    regions = []
    for r in oci.pagination.list_call_get_all_results(
        identity.list_region_subscriptions, tenancy_id
    ).data:
        if r.status == "READY":
            regions.append(r.region_name)

    compartments = [(tenancy_id, "(root)")]
    for c in oci.pagination.list_call_get_all_results(
        identity.list_compartments, tenancy_id, compartment_id_in_subtree=True
    ).data:
        if c.lifecycle_state == "ACTIVE":
            compartments.append((c.id, c.name))

    instances = []
    stopped = []
    paid_found = []
    stop_errors = []
    a1_ocpus = 0.0
    a1_mem = 0.0
    e2_count = 0
    for region in regions:
        cfg = dict(config)
        cfg["region"] = region
        compute = oci.core.ComputeClient(cfg)
        for comp_id, comp_name in compartments:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    compute.list_instances, comp_id
                )
            except oci.exceptions.ServiceError as e:
                instances.append(
                    {"region": region, "compartment": comp_name, "error": str(e)}
                )
                continue
            for inst in resp.data:
                ocpus = inst.shape_config.ocpus if inst.shape_config else None
                mem = inst.shape_config.memory_in_gbs if inst.shape_config else None
                rec = {
                    "name": inst.display_name,
                    "id": inst.id,
                    "shape": inst.shape,
                    "state": inst.lifecycle_state,
                    "region": region,
                    "compartment": comp_name,
                    "ocpus": ocpus,
                    "memory": mem,
                }
                instances.append(rec)
                if inst.lifecycle_state != "RUNNING":
                    continue
                if inst.shape == "VM.Standard.A1.Flex":
                    a1_ocpus += ocpus or 0
                    a1_mem += mem or 0
                elif inst.shape == "VM.Standard.E2.1.Micro":
                    e2_count += 1
                elif inst.shape not in FREE_SHAPES:
                    paid_found.append(rec)
                    if inst.display_name in NEVER_STOP_NAMES:
                        continue
                    try:
                        compute.instance_action(inst.id, "STOP")
                        stopped.append(rec)
                    except oci.exceptions.ServiceError as e:
                        stop_errors.append(
                            {"instance": inst.display_name, "error": str(e)}
                        )

    free_over = []
    if a1_ocpus > A1_OCPU_LIMIT or a1_mem > A1_MEM_LIMIT:
        free_over.append(
            f"A1 超免费额度: {a1_ocpus} OCPU / {a1_mem} GB (上限 4 OCPU / 24 GB)"
        )
    if e2_count > E2_COUNT_LIMIT:
        free_over.append(f"E2.1.Micro {e2_count} 台 (免费上限 2 台)")

    return {
        "profile": profile,
        "name": acct["name"],
        "tenancy": tenancy_id,
        "mtd_cost": round(mtd_cost, 4),
        "currency": currency,
        "budget": BUDGET_SGD,
        "over_budget": mtd_cost > BUDGET_SGD,
        "regions": regions,
        "instances": instances,
        "paid_running": paid_found,
        "stopped": stopped,
        "stop_errors": stop_errors,
        "a1_ocpus": a1_ocpus,
        "a1_mem": a1_mem,
        "e2_count": e2_count,
        "free_over": free_over,
    }


def main():
    now = datetime.now(timezone.utc)
    os.makedirs(BASE, exist_ok=True)
    state = {}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            state = json.load(f)

    report = {"checked_at": now.isoformat(), "accounts": [], "alerts": [], "errors": []}
    new_state = {}
    for acct in ACCOUNTS:
        try:
            res = check_account(acct, now)
        except Exception as e:
            report["errors"].append({"account": acct["name"], "error": str(e)})
            continue
        report["accounts"].append(res)
        prev = state.get(res["name"], {})
        prev_cost = prev.get("mtd_cost")
        delta = None
        if prev_cost is not None:
            delta = round(res["mtd_cost"] - prev_cost, 4)
        res["prev_mtd_cost"] = prev_cost
        res["mtd_delta"] = delta
        new_state[res["name"]] = {
            "mtd_cost": res["mtd_cost"],
            "checked_at": now.isoformat(),
        }

        if res["stopped"]:
            for s in res["stopped"]:
                report["alerts"].append(
                    f"[{res['name']}] 已自动停掉付费实例 {s['name']} ({s['shape']}, {s['region']})"
                )
        if res["stop_errors"]:
            for s in res["stop_errors"]:
                report["alerts"].append(
                    f"[{res['name']}] 付费实例 {s['instance']} 停机失败: {s['error']}"
                )
        for p in res["paid_running"]:
            if p not in res["stopped"]:
                report["alerts"].append(
                    f"[{res['name']}] 发现付费实例在跑但未停（在保护名单）: {p['name']} ({p['shape']}, {p['region']})"
                )
        if delta is not None and delta > DELTA_THRESHOLD:
            report["alerts"].append(
                f"[{res['name']}] 本月费用新增 {CURRENCY} {delta}，当前 {CURRENCY} {res['mtd_cost']}（预算 {CURRENCY} {BUDGET_SGD}）"
            )
        if res["free_over"]:
            for f in res["free_over"]:
                report["alerts"].append(f"[{res['name']}] {f}，超出部分会收费")

    bark_sent = False
    bark_error = ""
    if report["alerts"] or report["errors"]:
        lines = list(report["alerts"])
        for e in report["errors"]:
            lines.append(f"[{e['account']}] 检查失败: {e['error']}")
        summary_lines = [
            f"{a['name']}: 本月 {CURRENCY} {a['mtd_cost']} (预算 {BUDGET_SGD})"
            for a in report["accounts"]
        ]
        body = "\n".join(lines[:6] + [""] + summary_lines)
        bark_sent, bark_error = send_bark(BARK_TITLE, body)
    report["bark_sent"] = bark_sent
    report["bark_error"] = bark_error

    with open(STATE_FILE, "w") as f:
        json.dump(new_state, f, indent=2)
    with open(INVENTORY_FILE, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    report["action_needed"] = bool(report["alerts"] or report["errors"])
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
