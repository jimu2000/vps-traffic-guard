#!/bin/bash
# ============================================================================
# bark_enc.sh — Bark 加密推送脚本
#
# 功能：
# 向 Bark App 发送端到端加密的推送通知。推送内容在本地用 AES-256-CBC
# 加密后再发出，只有你的 Bark App 能解密，即使推送经过第三方服务器，
# 内容也不会泄露。每次推送使用全新的随机 IV。
#
# 使用要求：
# - Bark App（iOS）已启用加密：设置 → 加密 → 算法 AES256、模式 CBC、
# 填充 pkcs7，并设置了 32 位加密 Key
# - 系统已安装：bash、openssl、curl、python3
#
# 使用方法：
# 1. 直接运行：./bark_enc.sh "标题" "内容" [提示音]
# 例：./bark_enc.sh "服务器报警" "CPU 使用率 95%" "alarm"
# 2. 在其他脚本里引用：
# source /path/to/bark_enc.sh
# bark_enc "标题" "内容" "alarm"
#
# 提示音可选：alarm（报警）、minuet、telegraph 等 Bark 支持的提示音，
# 不填则使用 Bark 默认提示音。
# ============================================================================

# ============================================================================
# ★★★ 需要修改的配置（都在这里，改完就能用）★★★
# ============================================================================

# Bark 设备 Key
# 在 Bark App 里查看：打开 Bark App，设备 Key 就显示在首页（一串字母数字）。
# 把下面 xxxxxxxxx 换成你的设备 Key。
BARK_DEVICE_KEY="xxxxxxxxx"

# Bark 加密 Key（32 位）
# 在 Bark App 里设置：设置 → 加密 → 开启加密后设置的 Key。
# 必须和 App 里设置的 Key 完全一致，否则 App 解不开。
# 把下面 xxxxxxxxx 换成你的加密 Key。
BARK_ENC_KEY="xxxxxxxxx"

# Bark 服务器地址（自建 Bark 服务端才需要改，默认用官方服务器）
BARK_SERVER="https://api.day.app"

# ============================================================================
# 以下一般不用改
# ============================================================================

# 发送加密 Bark 推送
# 用法：bark_enc "标题" "内容" [提示音]
# 返回 0 表示 Bark 服务器已接受（code 200），非 0 表示发送失败。
bark_enc() {
local _title="$1" _body="$2" _sound="$3"
local _iv _key_hex _iv_hex _json _ct _resp

# 检查配置是否已修改
if [ "$BARK_DEVICE_KEY" = "xxxxxxxxx" ] || [ -z "$BARK_DEVICE_KEY" ]; then
echo "错误：请先在脚本顶部把 BARK_DEVICE_KEY 改成你的 Bark 设备 Key" >&2
return 1
fi
if [ "$BARK_ENC_KEY" = "xxxxxxxxx" ] || [ -z "$BARK_ENC_KEY" ]; then
echo "错误：请先在脚本顶部把 BARK_ENC_KEY 改成你的 Bark 加密 Key" >&2
return 1
fi

# 每次推送生成一个全新的随机 16 位 IV
_iv=$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
[ ${#_iv} -eq 16 ] || { echo "错误：生成随机 IV 失败" >&2; return 1;}

# openssl 只接受 hex 格式的 Key 和 IV
_key_hex=$(printf '%s' "$BARK_ENC_KEY" | od -An -tx1 -v | tr -d ' \n')
_iv_hex=$(printf '%s' "$_iv" | od -An -tx1 -v | tr -d ' \n')

# 构造 JSON 载荷（用 python3 处理转义，支持中文和特殊字符）
_json=$(python3 -c 'import json,sys; d={"title":sys.argv[1],"body":sys.argv[2]}; d.update({"sound":sys.argv[3]} if sys.argv[3] else {}); print(json.dumps(d, ensure_ascii=False))' "$_title" "$_body" "$_sound") || { echo "错误：构造 JSON 失败" >&2; return 1;}

# AES-256-CBC 加密，base64 编码
_ct=$(printf '%s' "$_json" | openssl enc -aes-256-cbc -K "$_key_hex" -iv "$_iv_hex" | base64 -w 0) || { echo "错误：加密失败" >&2; return 1;}

# POST 到 Bark 服务器（密文 + IV）
_resp=$(curl -s --max-time 15 -X POST "$BARK_SERVER/$BARK_DEVICE_KEY/" --data-urlencode "ciphertext=$_ct" --data-urlencode "iv=$_iv")
if printf '%s' "$_resp" | grep -q '"code":200'; then
return 0
else
echo "错误：Bark 服务器返回异常：$_resp" >&2
return 1
fi
}

# 直接运行时：./bark_enc.sh "标题" "内容" [提示音]
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
if [ $# -lt 2 ]; then
echo "用法：$0 \"标题\" \"内容\" [提示音]" >&2
echo "示例：$0 \"测试\" \"加密推送测试成功\" \"alarm\"" >&2
exit 1
fi
if bark_enc "$1" "$2" "$3"; then
echo "推送已发送（Bark 服务器返回成功）"
else
exit 1
fi
fi
