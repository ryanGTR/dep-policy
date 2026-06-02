#!/usr/bin/env bash
#
# cooldown-check.sh — 檢查套件版本距離發布日是否已過 cooldown 期
#
# 為什麼要 cooldown：
#   xz-utils 後門 2024-02 發布、2024-03 被發現；polyfill.io 劫持也是發布後幾週內爆。
#   要求新版本必須「年滿 N 天」才能入庫，給社群時間發現惡意 / 嚴重瑕疵。
#
# 用法:
#   ./cooldown-check.sh <coord> [<min_days>]
#
#   coord 格式：
#     Maven:  groupId:artifactId:version
#     npm:    name@version  或  @scope/name@version
#
#   min_days 預設 30
#
# Exit code: 0 通過 / 1 cooldown 內 / 2 找不到版本 / 3 不認得格式

set -euo pipefail

C_GREEN=$'\033[0;32m'; C_RED=$'\033[0;31m'; C_YELLOW=$'\033[0;33m'; C_RESET=$'\033[0m'
ok()   { echo "${C_GREEN}  ✓ $1${C_RESET}"; }
warn() { echo "${C_YELLOW}  ⚠ $1${C_RESET}"; }
fail() { echo "${C_RED}  ✗ $1${C_RESET}"; exit "${2:-1}"; }

COORD="${1:-}"
MIN_DAYS="${2:-30}"

[ -z "$COORD" ] && { grep '^#' "$0" | head -16 | sed 's/^# \{0,1\}//'; exit 1; }

# ─────────────── ecosystem 判斷 ───────────────

if [[ "$COORD" =~ ^@?[a-zA-Z0-9._-]+/?[a-zA-Z0-9._-]*@[a-zA-Z0-9.+\-]+$ ]]; then
    ECO="npm"
elif [[ "$COORD" =~ ^[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+:[a-zA-Z0-9.+\-]+$ ]]; then
    ECO="maven"
else
    fail "認不出 coord 格式: $COORD（Maven=g:a:v, npm=name@ver）" 3
fi

# ─────────────── 查發布日 ───────────────

case "$ECO" in
    maven)
        G="${COORD%%:*}"; REST="${COORD#*:}"
        A="${REST%%:*}"; V="${REST#*:}"
        # search.maven.org 的 timestamp 是 epoch millis
        # 例：q=g:org.apache.logging.log4j+AND+a:log4j-core+AND+v:2.14.1
        URL="https://search.maven.org/solrsearch/select?q=g:${G}+AND+a:${A}+AND+v:${V}&rows=1&wt=json"
        RESP=$(curl -fsS "$URL" || echo '{}')
        EPOCH_MS=$(echo "$RESP" | jq -r '.response.docs[0].timestamp // empty')
        if [ -z "$EPOCH_MS" ] || [ "$EPOCH_MS" = "null" ]; then
            fail "Maven Central 找不到 $G:$A:$V" 2
        fi
        EPOCH=$((EPOCH_MS / 1000))
        ;;
    npm)
        # 拆 name + version
        # name 可以是 @scope/name 或 plain name
        if [[ "$COORD" =~ ^@([^/]+)/([^@]+)@(.+)$ ]]; then
            PKG="@${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
            V="${BASH_REMATCH[3]}"
        elif [[ "$COORD" =~ ^([^@]+)@(.+)$ ]]; then
            PKG="${BASH_REMATCH[1]}"
            V="${BASH_REMATCH[2]}"
        else
            fail "解析不出 npm coord: $COORD" 3
        fi
        # registry.npmjs.org/{pkg} 的 .time.{version} 是 ISO 8601
        URL_ENC=$(echo "$PKG" | sed 's|/|%2F|g')
        RESP=$(curl -fsS "https://registry.npmjs.org/$URL_ENC" || echo '{}')
        ISO=$(echo "$RESP" | jq -r --arg v "$V" '.time[$v] // empty')
        if [ -z "$ISO" ] || [ "$ISO" = "null" ]; then
            fail "npm registry 找不到 $PKG@$V" 2
        fi
        EPOCH=$(date -d "$ISO" +%s)
        ;;
esac

# ─────────────── 計算 age + 判定 ───────────────

NOW=$(date +%s)
AGE_DAYS=$(( (NOW - EPOCH) / 86400 ))
RELEASE_DATE=$(date -d "@$EPOCH" +%Y-%m-%d)

echo "  coord:        $COORD"
echo "  ecosystem:    $ECO"
echo "  released:     $RELEASE_DATE ($AGE_DAYS days ago)"
echo "  min_age:      $MIN_DAYS days"

if [ "$AGE_DAYS" -ge "$MIN_DAYS" ]; then
    ok "Cooldown PASS — 套件已年滿 $MIN_DAYS 天"
    exit 0
else
    REMAIN=$((MIN_DAYS - AGE_DAYS))
    echo "${C_RED}  ✗ Cooldown FAIL — 還要等 $REMAIN 天${C_RESET}"
    echo "${C_YELLOW}  說明: cooldown 機制保護期，避免拉到剛上架的 malicious 套件。${C_RESET}"
    echo "${C_YELLOW}  選項: 1) 等到 $(date -d "$RELEASE_DATE + $MIN_DAYS days" +%Y-%m-%d) 再合 MR${C_RESET}"
    echo "${C_YELLOW}        2) 用更早、已經 cooldown 完的版本${C_RESET}"
    echo "${C_YELLOW}        3) Security override（yaml 加 cooldown_override: <理由>）— 需 senior security approve${C_RESET}"
    exit 1
fi
