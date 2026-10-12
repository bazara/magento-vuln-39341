#!/usr/bin/env bash
#
# APSB26-146 / CVE-2026-75650 - hotfix VULN-39341 for Magento Open Source / Adobe Commerce 2.4.4 - 2.4.9
# https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146
#
# Detects the Magento version, downloads the matching official hotfix from repo.magento.com,
# verifies it against a pinned SHA-256, backs up every file it touches, then applies it.
# Only changes files: it prints the bin/magento commands to run afterwards but never runs them.
#
# Usage:
#   apply-VULN-39341.sh check    <magento_root> [options]     # dry run, changes nothing
#   apply-VULN-39341.sh apply    <magento_root> [options]     # download, verify, back up, patch
#   apply-VULN-39341.sh rollback <magento_root> <backup_dir>  # restore files from a backup
#   apply-VULN-39341.sh download <version|patch_id> [options] # fetch + verify into the cache only
#   apply-VULN-39341.sh list                                  # which patch covers which version
#
# Options:
#   --version V        skip auto-detection and treat the install as Magento V (e.g. 2.4.7-p3)
#   --patch-id ID      force a patch from 'list' (e.g. 248-p3) regardless of version
#   --patch-file FILE  use a local .patch or .zip instead of downloading (still SHA-256 verified)
#   --url URL          download from URL instead of the pinned Adobe URL (requires --sha256)
#   --sha256 HASH      expected SHA-256 of the .patch (for --url, or if Adobe re-issues a patch)
#   --backup-dir DIR   backup location (default: ~/magento-backups/VULN-39341-<timestamp>)
#   --cache-dir DIR    download cache (default: ~/.cache/magento-hotfixes/VULN-39341)
#   -y, --yes          never prompt (for automation)
#   -h, --help         show this help

set -euo pipefail

VULN="VULN-39341"
BULLETIN="https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146"

# id | download URL | file inside the zip | SHA-256 of that .patch file (verified 2026-10-12)
PATCHES='
249|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_249.patch|8df23110e1909e2d5f0c2f0ecbe7f803670dfb0c9c3d15a527371c04b7825bf7
248-p5|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_248-p5.patch|75266ec5548f356a0572c2af74ee5f05aadfab40ede374e8d39bc4a39b6b8ec8
247-p10|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_247-p10.patch|fbf4019da673f96410c07aa970453bc22dfb6289aed1df26a87a53ca85e76f1d
246-p15|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_246-p15.patch|ecb778f71d3e57e67251496a1846b8f548f4c2b2cbde762e2a4274c2c905bd1d
245-p17|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_245-p17.patch|a2496efe386cccbf260182436286401099f31392ff732c9f50d363ff83e6a4dd
244-p18|https://repo.magento.com/patch/VULN-39341-composer-patches.zip|VULN_39341_composer_patches/VULN-39341_244-p18.patch|a2496efe386cccbf260182436286401099f31392ff732c9f50d363ff83e6a4dd
248-p3|https://repo.magento.com/patch/VULN-39341-248-p3-patch.zip|VULN-39341_248-p3.patch|bb8df75f0fd542ea03368e36cf7c19e1e2c109ed4c0c9609f21aa6577cb523b9
248-p1|https://repo.magento.com/patch/VULN-39341-248-p1-patch.zip|VULN-39341_248-p1.patch|3df94078e4feb10d767c6ab52ed5e5c82bb6d2f29e71bf34d3e81355d878f386
247-p8|https://repo.magento.com/patch/VULN-39341-247-p8-patch.zip|VULN-39341_247-p8.patch|fbe6ba6fb43ea56c2824ab9d3e4973dc942949a0ccb7dce23afc648a89843f30
247-p5|https://repo.magento.com/patch/VULN-39341-247-p5-patch.zip|VULN-39341_247-p5.patch|0fc86d7b41afb121e7cdab59f0a4d8456f33edd4e1ed5dc32ec99bb9cc50bc5d
246-p13|https://repo.magento.com/patch/VULN-39341-246-p13-patch.zip|VULN-39341_246-p13.patch|4d32c7628318c8720c90954edb902e3ea501f0a0d03a47eafa62c44cfd84a4c3
246-p11|https://repo.magento.com/patch/VULN-39341-246-p11-patch.zip|VULN-39341_246-p11.patch|6b7a95a473c5fdc2d7d1ee303a1cc8f9acb327a94ae271cd83804de5531bdc28
'

list_patches() {
    cat <<'EOF'
Patch id  Magento versions (per APSB26-146)
249       2.4.9-2026-aug, 2.4.9-2026-jul
248-p5    2.4.8-2026-aug, 2.4.8-2026-jul, 2.4.8-p5, 2.4.8-p4
248-p3    2.4.8-p3, 2.4.8-p2
248-p1    2.4.8-p1, 2.4.8
247-p10   2.4.7-2026-aug, 2.4.7-2026-jul, 2.4.7-p10, 2.4.7-p9
247-p8    2.4.7-p8, 2.4.7-p7
247-p5    2.4.7 - 2.4.7-p6
246-p15   2.4.6-2026-aug, 2.4.6-2026-jul, 2.4.6-p15, 2.4.6-p14
246-p13   2.4.6-p13, 2.4.6-p12, 2.4.5-p15, 2.4.5-p14, 2.4.4-p16, 2.4.4-p15
246-p11   2.4.6 - 2.4.6-p11, 2.4.5 - 2.4.5-p13, 2.4.4 - 2.4.4-p14
245-p17   2.4.5-2026-aug, 2.4.5-2026-jul, 2.4.5-p17, 2.4.5-p16
244-p18   2.4.4-2026-aug, 2.4.4-2026-jul, 2.4.4-p18, 2.4.4-p17
EOF
}

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }
info() { echo "==> $*"; }

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit "${1:-1}"; }

confirm() {
    [ "$YES" = 1 ] && return 0
    [ -t 0 ] || die "$1 - refusing to continue non-interactively (pass --yes to override)"
    local a; read -r -p "$1 Continue anyway? [y/N] " a
    [ "$a" = "y" ] || [ "$a" = "Y" ] || exit 1
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

file_owner() { stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1"; }
file_user()  { stat -c '%U' "$1" 2>/dev/null || stat -f '%Su' "$1" 2>/dev/null || true; }

patch_field() { printf '%s\n' "$PATCHES" | awk -F'|' -v id="$1" -v n="$2" '$1 == id {print $n; exit}'; }

# Map a Magento version to the patch id Adobe lists for it.
resolve_patch_id() {
    local v="${1#v}" minor p
    if [[ "$v" =~ ^2\.4\.([4-9])-2026-(jul|aug)$ ]]; then
        case "${BASH_REMATCH[1]}" in
            9) echo 249 ;; 8) echo 248-p5 ;; 7) echo 247-p10 ;;
            6) echo 246-p15 ;; 5) echo 245-p17 ;; 4) echo 244-p18 ;;
        esac
        return 0
    fi
    [[ "$v" =~ ^2\.4\.([4-8])(-p([0-9]+))?$ ]] || return 1
    minor="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[3]:-0}"
    case "$minor:$p" in
        8:4|8:5)                          echo 248-p5 ;;
        8:2|8:3)                          echo 248-p3 ;;
        8:0|8:1)                          echo 248-p1 ;;
        7:9|7:10)                         echo 247-p10 ;;
        7:7|7:8)                          echo 247-p8 ;;
        7:[0-6])                          echo 247-p5 ;;
        6:14|6:15)                        echo 246-p15 ;;
        5:16|5:17)                        echo 245-p17 ;;
        4:17|4:18)                        echo 244-p18 ;;
        6:12|6:13|5:14|5:15|4:15|4:16)    echo 246-p13 ;;
        6:[0-9]|6:1[01]|5:[0-9]|5:1[0-3]|4:[0-9]|4:1[0-4]) echo 246-p11 ;;
        *) return 1 ;;
    esac
}

# --- Download / extract helpers ----------------------------------------------------
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
    else
        die "Need curl or wget to download the patch (or pass --patch-file)"
    fi
}

is_zip() { [ "$(head -c 2 "$1")" = "PK" ]; }

zip_members() {
    if command -v unzip >/dev/null 2>&1; then unzip -Z1 "$1"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys,zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$1"
    elif command -v bsdtar >/dev/null 2>&1; then bsdtar -tf "$1"
    else die "Need unzip, python3 or bsdtar to extract the patch zip"; fi
}

zip_extract() {
    if command -v unzip >/dev/null 2>&1; then unzip -p "$1" "$2" > "$3"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys,zipfile; sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' "$1" "$2" > "$3"
    else bsdtar -xOf "$1" "$2" > "$3"; fi
}

# Download (or reuse from cache) the patch for $1, verify its SHA-256, set PATCH_SRC/PATCH_NAME/PATCH_URL/PATCH_SHA.
obtain_patch() {
    local id="$1" member="" name src dl="$WORK/download" got zip_sha=""
    if [ -n "$URL_OPT" ]; then
        [ -n "$SHA_OPT" ] || die "--url requires --sha256 <expected sha256 of the .patch>"
        PATCH_URL="$URL_OPT"; PATCH_SHA="$SHA_OPT"
        name="$VULN-custom-${SHA_OPT:0:12}.patch"
    else
        PATCH_URL="$(patch_field "$id" 2)"
        [ -n "$PATCH_URL" ] || die "Unknown patch id '$id' (see: $0 list)"
        member="$(patch_field "$id" 3)"
        PATCH_SHA="${SHA_OPT:-$(patch_field "$id" 4)}"
        name="$(basename "$member")"
    fi
    PATCH_SHA="$(echo "$PATCH_SHA" | tr 'A-F' 'a-f')"
    PATCH_NAME="$name"

    local cached="$CACHE_DIR/$name"
    if [ -z "$PATCH_FILE_OPT" ] && [ -f "$cached" ] && [ "$(sha256 "$cached")" = "$PATCH_SHA" ]; then
        info "Using cached $cached (sha256 OK)"
        PATCH_SRC="$cached"
        return 0
    fi

    if [ -n "$PATCH_FILE_OPT" ]; then
        [ -f "$PATCH_FILE_OPT" ] || die "Patch file not found: $PATCH_FILE_OPT"
        cp "$PATCH_FILE_OPT" "$dl"
        PATCH_URL="file://$PATCH_FILE_OPT"
    else
        info "Downloading $PATCH_URL"
        fetch "$PATCH_URL" "$dl" || die "Download failed: $PATCH_URL"
    fi

    if is_zip "$dl"; then
        zip_sha="$(sha256 "$dl")"
        local m pick=""
        while IFS= read -r m; do
            case "$m" in __MACOSX/*|*/) continue ;; esac
            if [ -n "$member" ]; then
                [ "$(basename "$m")" = "$name" ] && { pick="$m"; break; }
            else
                case "$m" in *.patch) [ -z "$pick" ] || die "Zip has several .patch files - pass --patch-id"; pick="$m" ;; esac
            fi
        done < <(zip_members "$dl")
        [ -n "$pick" ] || die "No ${name:-.patch file} inside the downloaded zip"
        src="$WORK/extracted.patch"
        zip_extract "$dl" "$pick" "$src"
    else
        src="$dl"
    fi

    got="$(sha256 "$src")"
    if [ "$got" != "$PATCH_SHA" ]; then
        die "SHA-256 mismatch for $name
  expected: $PATCH_SHA
  got:      $got
Nothing was changed. If Adobe re-issued the hotfix, check the bulletin and rerun with --sha256 <new hash>:
  $BULLETIN"
    fi

    mkdir -p "$CACHE_DIR"
    cp "$src" "$cached"
    local sums="$CACHE_DIR/SHA256SUMS"
    { grep -v "  $name\$" "$sums" 2>/dev/null || true; echo "$PATCH_SHA  $name"; } > "$WORK/sums" && mv "$WORK/sums" "$sums"
    [ -z "$zip_sha" ] || echo "$zip_sha  $PATCH_URL  $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CACHE_DIR/downloads.log"
    info "Verified $name (sha256 $PATCH_SHA), cached in $CACHE_DIR"
    PATCH_SRC="$cached"
}

# --- Post-change instructions --------------------------------------------------------
magento_mode() {
    command -v "$PHP_BIN" >/dev/null 2>&1 || { echo unknown; return; }
    php_q -r '$e = @include $argv[1]; echo (is_array($e) && !empty($e["MAGE_MODE"])) ? $e["MAGE_MODE"] : "default";' \
        "$ROOT/app/etc/env.php" || echo unknown
}

print_next_steps() {
    local owner run="" mode
    owner="$(file_user "$ROOT/bin/magento")"
    [ -n "$owner" ] && [ "$owner" != "$(id -un)" ] && run="sudo -u $owner "
    mode="$(magento_mode)"
    echo
    echo "Next steps - run these yourself (as the Magento file owner${owner:+: $owner}). Deploy mode: $mode"
    echo "  cd $ROOT"
    echo "  ${run}bin/magento maintenance:enable"
    echo "  ${run}rm -rf generated/code/* generated/metadata/*"
    case "$mode" in
        developer|default) echo "  # $mode mode: generated classes are rebuilt on demand, setup:di:compile is optional" ;;
        *)                 echo "  ${run}bin/magento setup:di:compile        # REQUIRED: BlockFactory constructor changed" ;;
    esac
    echo "  ${run}bin/magento cache:flush"
    echo "  ${run}bin/magento maintenance:disable"
    echo "  # if OPcache has validate_timestamps=0, also reload PHP-FPM (e.g. sudo systemctl reload php8.3-fpm)"
}

# --- Argument parsing -----------------------------------------------------------------
VERSION_OPT="" PATCH_ID_OPT="" PATCH_FILE_OPT="" URL_OPT="" SHA_OPT="" BACKUP_OPT="" YES=0
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/magento-hotfixes/$VULN"
PHP_BIN="${PHP_BIN:-php}"
php_q() { "$PHP_BIN" -d display_startup_errors=0 -d display_errors=0 "$@" 2>/dev/null; }
POS=()
need() { [ "$1" -ge 2 ] || die "$2 needs a value"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --version)    need $# "$1"; VERSION_OPT="$2"; shift 2 ;;
        --patch-id)   need $# "$1"; PATCH_ID_OPT="$2"; shift 2 ;;
        --patch-file) need $# "$1"; PATCH_FILE_OPT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"; shift 2 ;;
        --url)        need $# "$1"; URL_OPT="$2"; shift 2 ;;
        --sha256)     need $# "$1"; SHA_OPT="$2"; shift 2 ;;
        --backup-dir) need $# "$1"; BACKUP_OPT="$2"; shift 2 ;;
        --cache-dir)  need $# "$1"; CACHE_DIR="$2"; shift 2 ;;
        -y|--yes)     YES=1; shift ;;
        -h|--help)    usage 0 ;;
        -*)           die "Unknown option: $1 (see --help)" ;;
        *)            POS+=("$1"); shift ;;
    esac
done
[ -z "$SHA_OPT" ] || [[ "$SHA_OPT" =~ ^[0-9a-fA-F]{64}$ ]] || die "--sha256 must be 64 hex characters"

ACTION="${POS[0]:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "$ACTION" in
    list) list_patches; exit 0 ;;
    download)
        arg="${POS[1]:-${PATCH_ID_OPT:-$VERSION_OPT}}"
        [ -n "$arg" ] || [ -n "$URL_OPT" ] || die "Usage: $0 download <version|patch_id>"
        if [ -n "$URL_OPT" ] || [ -n "$(patch_field "$arg" 2)" ]; then id="${arg:-custom}"
        else id="$(resolve_patch_id "$arg")" || die "No $VULN hotfix listed for '$arg' (see: $0 list)"; fi
        obtain_patch "$id"
        echo "$PATCH_SRC"
        exit 0 ;;
    check|apply|rollback) ;;
    *) usage ;;
esac

[ ${#POS[@]} -ge 2 ] || usage
ROOT="$(cd "${POS[1]}" 2>/dev/null && pwd)" || die "Magento root not found: ${POS[1]}"
[ -f "$ROOT/app/etc/env.php" ] || [ -f "$ROOT/app/etc/di.xml" ] || die "$ROOT does not look like a Magento root"
[ -z "${POS[2]:-}" ] || BACKUP_OPT="${POS[2]}"

# --- Rollback (needs no download) ---------------------------------------------------
if [ "$ACTION" = "rollback" ]; then
    BACKUP="$BACKUP_OPT"
    [ -n "$BACKUP" ] && [ -f "$BACKUP/files.tar" ] || die "Give the backup dir containing files.tar"
    if [ -f "$BACKUP/INFO" ] && ! grep -qx "root=$ROOT" "$BACKUP/INFO"; then
        confirm "Backup was taken from $(grep '^root=' "$BACKUP/INFO" | cut -d= -f2-), not $ROOT."
    fi
    info "Restoring files from $BACKUP/files.tar"
    (cd "$ROOT" && tar -xpf "$BACKUP/files.tar")
    if [ -f "$BACKUP/SHA256SUMS.before" ]; then
        (cd "$ROOT" && while read -r sum f; do
            [ "$(sha256 "$f")" = "$sum" ] || die "Checksum mismatch after restore: $f"
        done < "$BACKUP/SHA256SUMS.before")
        info "All restored files match their pre-patch checksums."
    fi
    info "Rollback complete."
    print_next_steps
    exit 0
fi

command -v patch >/dev/null 2>&1 || die "'patch' command not found. Install it: 'dnf install -y patch' (Amazon Linux 2023/RHEL), 'yum install -y patch' (Amazon Linux 2/CentOS 7), or 'apt-get install -y patch' (Debian/Ubuntu)"

# --- Version -> patch -----------------------------------------------------------------
detect_version() {
    local v=""
    if [ -f "$ROOT/composer.lock" ] && command -v "$PHP_BIN" >/dev/null 2>&1; then
        v="$(php_q -r '$l=json_decode(file_get_contents($argv[1]),true);foreach($l["packages"] as $p){if(in_array($p["name"],["magento/product-enterprise-edition","magento/product-community-edition","magento/magento2-base"])){echo $p["version"];break;}}' "$ROOT/composer.lock" || true)"
    fi
    if [ -z "$v" ] && [ -f "$ROOT/composer.json" ]; then
        v="$(grep -m1 '"version"' "$ROOT/composer.json" | sed 's/.*"version": *"\([^"]*\)".*/\1/' || true)"
    fi
    echo "${v#v}"
}

VERSION="${VERSION_OPT:-$(detect_version)}"
VERSION="${VERSION:-unknown}"
EXPECTED_ID="$(resolve_patch_id "$VERSION" || true)"

if [ -n "$PATCH_ID_OPT" ]; then
    PATCH_ID="$PATCH_ID_OPT"
    if [ -z "$URL_OPT" ] && [ "$PATCH_ID" != "$EXPECTED_ID" ]; then
        warn "Adobe lists patch '${EXPECTED_ID:-none}' for Magento $VERSION, but you forced '$PATCH_ID'."
        [ "$ACTION" = "check" ] || confirm "Patch/version mismatch."
    fi
elif [ -n "$URL_OPT" ]; then
    PATCH_ID="custom"
elif [ -n "$EXPECTED_ID" ]; then
    PATCH_ID="$EXPECTED_ID"
else
    die "No $VULN hotfix is listed for Magento '$VERSION'.
Run '$0 list' and pass --patch-id (or --version if detection is wrong). Bulletin: $BULLETIN"
fi

# --- Prepare the patch for this install layout ---------------------------------------
obtain_patch "$PATCH_ID"
PATCH_FILE="$WORK/$PATCH_NAME"

if [ -d "$ROOT/vendor/magento/framework" ]; then
    LAYOUT="composer"
    cp "$PATCH_SRC" "$PATCH_FILE"
elif [ -d "$ROOT/lib/internal/Magento/Framework" ]; then
    # git-clone install: modules live in app/code, framework in lib/internal
    LAYOUT="git"
    sed -e 's#vendor/magento/module-backend/#app/code/Magento/Backend/#g' \
        -e 's#vendor/magento/module-email/#app/code/Magento/Email/#g' \
        -e 's#vendor/magento/module-newsletter/#app/code/Magento/Newsletter/#g' \
        -e 's#vendor/magento/framework/#lib/internal/Magento/Framework/#g' \
        "$PATCH_SRC" > "$PATCH_FILE"
else
    die "Cannot find vendor/magento/framework or lib/internal/Magento/Framework under $ROOT"
fi

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(grep '^+++ b/' "$PATCH_FILE" | sed 's#^+++ b/##')
[ ${#FILES[@]} -gt 0 ] || die "Patch $PATCH_NAME lists no files"

info "Magento root : $ROOT ($LAYOUT layout)"
info "Version      : $VERSION"
info "Patch        : $PATCH_ID -> $PATCH_NAME"
info "Source       : $PATCH_URL"
info "SHA-256      : $PATCH_SHA (verified)"

is_applied() { (cd "$ROOT" && patch -p1 -R --dry-run -s -f < "$PATCH_FILE" >/dev/null 2>&1); }
can_apply()  { (cd "$ROOT" && patch -p1 -N --dry-run -f < "$PATCH_FILE"); }

case "$ACTION" in
# ---------------------------------------------------------------------------------
check)
    for f in "${FILES[@]}"; do
        [ -f "$ROOT/$f" ] && echo "  found   $f" || echo "  MISSING $f"
    done
    if is_applied; then info "Patch is ALREADY APPLIED."; exit 0; fi
    info "Dry run:"
    if can_apply; then info "Patch applies cleanly. Run with 'apply' to install it."
    else die "Patch does NOT apply cleanly - files differ from stock Magento $VERSION (local edits, other patches, or wrong --patch-id)."; fi
    ;;
# ---------------------------------------------------------------------------------
apply)
    if is_applied; then info "Patch is already applied - nothing to do."; print_next_steps; exit 0; fi
    for f in "${FILES[@]}"; do [ -f "$ROOT/$f" ] || die "Missing file: $f"; done
    info "Dry run..."
    can_apply >/dev/null || { can_apply || true; die "Patch does not apply cleanly - nothing was changed."; }

    BACKUP="${BACKUP_OPT:-$HOME/magento-backups/$VULN-$(date +%Y%m%d-%H%M%S)}"
    mkdir -p "$BACKUP"
    BACKUP="$(cd "$BACKUP" && pwd)"
    info "Backing up ${#FILES[@]} files to $BACKUP"
    (cd "$ROOT" && tar -cpf "$BACKUP/files.tar" "${FILES[@]}")
    (cd "$ROOT" && for f in "${FILES[@]}"; do echo "$(sha256 "$f")  $f"; done) > "$BACKUP/SHA256SUMS.before"
    (cd "$ROOT" && for f in "${FILES[@]}"; do echo "$(file_owner "$f")  $f"; done) > "$BACKUP/OWNERS"
    cp "$PATCH_SRC" "$BACKUP/$PATCH_NAME"
    echo "$PATCH_SHA  $PATCH_NAME" > "$BACKUP/PATCH.SHA256"
    printf 'root=%s\nlayout=%s\nversion=%s\npatch_id=%s\npatch_url=%s\npatch_sha256=%s\ndate=%s\n' \
        "$ROOT" "$LAYOUT" "$VERSION" "$PATCH_ID" "$PATCH_URL" "$PATCH_SHA" "$(date)" > "$BACKUP/INFO"
    tar -tf "$BACKUP/files.tar" >/dev/null || die "Backup archive is unreadable - aborting before patching."

    info "Applying patch..."
    PATCH_OPTS=(-p1 -N -f)
    patch --version 2>/dev/null | grep -q GNU && PATCH_OPTS+=(--no-backup-if-mismatch)
    if ! (cd "$ROOT" && patch "${PATCH_OPTS[@]}" < "$PATCH_FILE"); then
        echo "Patch failed - restoring backup." >&2
        (cd "$ROOT" && tar -xpf "$BACKUP/files.tar")
        die "Restored original files from $BACKUP"
    fi
    find "$ROOT" \( -path "$ROOT/vendor/magento/*" -o -path "$ROOT/app/code/Magento/*" \
                    -o -path "$ROOT/lib/internal/*" -o -path "$ROOT/pub/errors/*" \) \
         \( -name '*.orig' -o -name '*.rej' \) -newer "$BACKUP/INFO" -delete 2>/dev/null || true

    # patch rewrites files, so when run as root they would end up root-owned
    if [ "$(id -u)" -eq 0 ]; then
        (cd "$ROOT" && while read -r owner f; do chown "$owner" "$f"; done < "$BACKUP/OWNERS")
    fi
    (cd "$ROOT" && for f in "${FILES[@]}"; do echo "$(sha256 "$f")  $f"; done) > "$BACKUP/SHA256SUMS.after"

    if command -v "$PHP_BIN" >/dev/null 2>&1; then
        info "PHP syntax check..."
        for f in "${FILES[@]}"; do "$PHP_BIN" -l "$ROOT/$f" >/dev/null || die "Syntax error in $f - run: $0 rollback $ROOT $BACKUP"; done
    fi
    is_applied || die "Verification failed - run: $0 rollback $ROOT $BACKUP"

    info "DONE. Patch applied and verified. Backup: $BACKUP"
    print_next_steps
    cat <<EOF

Also recommended by Adobe (see bulletin): rotate the encryption key, admin passwords,
integration/OAuth tokens, payment gateway and third-party API keys, and DB credentials.
  $BULLETIN

Verify later:  $0 check $ROOT
Rollback:      $0 rollback $ROOT $BACKUP
EOF
    if [ "$LAYOUT" = "composer" ]; then
        cat <<EOF

NOTE: 'composer install/update' rewrites vendor/ and pub/errors/ and will silently undo this
hotfix. Re-run this tool after every composer run/deploy, or add the verified patch
($BACKUP/$PATCH_NAME) to your deploy pipeline (on Adobe Commerce Cloud: m2-hotfixes/).
EOF
    fi
    ;;
esac
