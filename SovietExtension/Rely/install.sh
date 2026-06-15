#!/bin/bash

# 如果用户用 sh install.sh 执行，自动切换到 bash
# If user runs this script with sh, re-exec with bash.
if [ -z "${BASH_VERSION:-}" ]; then
    exec /bin/bash "$0" "$@"
fi

set -euo pipefail

# ==============================
# SovietExtension installer
# ==============================

APP_NAME="WeChat"
FRAMEWORK_NAME="${FRAMEWORK_NAME:-SovietExtension}"
APP_PATH="/Applications/${APP_NAME}.app"
FORCE=0
RUN_SUDO=0

die() {
    echo ""
    echo "❌ [ERROR] $*" >&2
    echo ""
    exit 1
}

warn() {
    echo "⚠️  [WARN] $*"
}

ok() {
    echo "✅ [OK] $*"
}

info() {
    echo "👉 [INFO] $*"
}

usage() {
    cat <<EOF
Usage:
  ./install.sh
  sh install.sh
  ./install.sh --force
  ./install.sh --app=/Applications/WeChat.app

Options:
  --force              Ignore version check and install anyway / 忽略版本检查，强制安装
  --app=PATH           Specify WeChat.app path / 指定 WeChat.app 路径
  --framework=NAME     Specify framework name, default: SovietExtension / 指定插件名，默认 SovietExtension
  -h, --help           Show help / 显示帮助

EOF
}

run_cmd() {
    if [ "${RUN_SUDO}" -eq 1 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

for arg in "$@"; do
    case "$arg" in
        --force)
            FORCE=1
            ;;
        --app=*)
            APP_PATH="${arg#--app=}"
            ;;
        --framework=*)
            FRAMEWORK_NAME="${arg#--framework=}"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument / 未知参数: ${arg}"
            ;;
    esac
done

APP_PATH="${APP_PATH%/}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MACOS_PATH="${APP_PATH}/Contents/MacOS"
INFO_PLIST="${APP_PATH}/Contents/Info.plist"
APP_EXECUTABLE_PATH="${MACOS_PATH}/${APP_NAME}"

PLUGIN_SRC_PATH="${SCRIPT_DIR}/Plugin/${FRAMEWORK_NAME}.framework"
FRAMEWORK_DST_PATH="${MACOS_PATH}/${FRAMEWORK_NAME}.framework"

INSERT_DYLIB_PATH="${SCRIPT_DIR}/insert_dylib"
SUPPORTED_FILE="${SCRIPT_DIR}/supported_versions.txt"

LOAD_DYLIB_PATH="@executable_path/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"
STATE_FILE="${MACOS_PATH}/.${FRAMEWORK_NAME}.install_state"

LOG_PATH="/tmp/YMWeChatAntiRevokePatch.log"

read_plist() {
    local key="$1"
    /usr/libexec/PlistBuddy -c "Print :${key}" "${INFO_PLIST}" 2>/dev/null || true
}

trim() {
    echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_build_token() {
    local value="$1"
    if [ "${value}" = "*" ]; then
        return 0
    fi

    if [[ "${value}" =~ ^[0-9]+$ ]]; then
        return 0
    fi

    return 1
}

check_basic_files() {
    [ -d "${APP_PATH}" ] || die "WeChat.app not found / 找不到 WeChat.app: ${APP_PATH}"
    [ -f "${INFO_PLIST}" ] || die "Info.plist not found / 找不到 Info.plist: ${INFO_PLIST}"
    [ -f "${APP_EXECUTABLE_PATH}" ] || die "WeChat executable not found / 找不到微信主可执行文件: ${APP_EXECUTABLE_PATH}"

    [ -d "${PLUGIN_SRC_PATH}" ] || die "Plugin framework not found / 找不到插件 framework: ${PLUGIN_SRC_PATH}"
    [ -e "${PLUGIN_SRC_PATH}/${FRAMEWORK_NAME}" ] || die "Framework binary not found / framework 内找不到同名二进制: ${PLUGIN_SRC_PATH}/${FRAMEWORK_NAME}"

    [ -f "${INSERT_DYLIB_PATH}" ] || die "insert_dylib not found / 找不到 insert_dylib: ${INSERT_DYLIB_PATH}"
    [ -f "${SUPPORTED_FILE}" ] || die "supported_versions.txt not found / 找不到版本控制文件: ${SUPPORTED_FILE}"
}

check_supported_version() {
    APP_SHORT_VERSION="$(read_plist CFBundleShortVersionString)"
    APP_BUILD_VERSION="$(read_plist CFBundleVersion)"

    [ -n "${APP_SHORT_VERSION}" ] || die "Failed to read CFBundleShortVersionString / 读取微信版本号失败"
    [ -n "${APP_BUILD_VERSION}" ] || die "Failed to read CFBundleVersion / 读取微信 build 号失败"

    MATCHED_DISPLAY_VERSION=""
    MATCHED_LINE=""

    echo ""
    info "Detected WeChat version / 检测到微信版本:"
    echo "    CFBundleShortVersionString: ${APP_SHORT_VERSION}"
    echo "    CFBundleVersion:            ${APP_BUILD_VERSION}"
    echo ""

    while IFS='|' read -r f1 f2 f3 f4 rest || [ -n "${f1:-}" ]; do
        f1="$(trim "${f1:-}")"
        f2="$(trim "${f2:-}")"
        f3="$(trim "${f3:-}")"
        f4="$(trim "${f4:-}")"

        [ -z "${f1}" ] && continue
        [[ "${f1}" == \#* ]] && continue

        local display_version=""
        local short_version=""
        local build_version=""
        local note=""

        # 新格式：
        # DisplayVersion|CFBundleShortVersionString|CFBundleVersion|Note
        #
        # 兼容旧格式：
        # CFBundleShortVersionString|CFBundleVersion|Note
        if [ -n "${f3}" ] && is_build_token "${f3}"; then
            display_version="${f1}"
            short_version="${f2}"
            build_version="${f3}"
            note="${f4}"
        else
            display_version="${f1}"
            short_version="${f1}"
            build_version="${f2}"
            note="${f3}"
        fi

        [ -z "${short_version}" ] && short_version="*"
        [ -z "${build_version}" ] && build_version="*"

        if { [ "${short_version}" = "${APP_SHORT_VERSION}" ] || [ "${short_version}" = "*" ]; } && \
           { [ "${build_version}" = "${APP_BUILD_VERSION}" ] || [ "${build_version}" = "*" ]; }; then
            MATCHED_DISPLAY_VERSION="${display_version}"
            MATCHED_LINE="${display_version}|${short_version}|${build_version}|${note}"
            break
        fi
    done < "${SUPPORTED_FILE}"

    if [ -n "${MATCHED_DISPLAY_VERSION}" ]; then
        ok "Version supported / 版本检查通过"
        echo "    Supported Display Version: ${MATCHED_DISPLAY_VERSION}"
        echo "    Matched Rule:              ${MATCHED_LINE}"
        echo ""

        BACKUP_PATH="${APP_EXECUTABLE_PATH}.backup.${MATCHED_DISPLAY_VERSION}.${APP_BUILD_VERSION}"
        return 0
    fi

    warn "Current WeChat version is not listed in supported_versions.txt / 当前微信版本未在支持列表中"
    echo "    Detected CFBundleShortVersionString: ${APP_SHORT_VERSION}"
    echo "    Detected CFBundleVersion:            ${APP_BUILD_VERSION}"
    echo ""
    echo "    Please add a line like / 请添加类似下面这一行："
    echo "    4.1.9.58|${APP_SHORT_VERSION}|${APP_BUILD_VERSION}|Tested"
    echo ""

    BACKUP_PATH="${APP_EXECUTABLE_PATH}.backup.${APP_SHORT_VERSION}.${APP_BUILD_VERSION}"

    if [ "${FORCE}" -eq 1 ]; then
        warn "Force mode enabled, continue anyway / 已使用 --force，继续安装"
        return 0
    fi

    read -r -p "Continue anyway? 是否仍然继续安装？[y/N] " answer
    case "${answer}" in
        y|Y|yes|YES)
            warn "User confirmed, continue installation / 用户确认继续安装"
            ;;
        *)
            die "Installation cancelled / 用户取消安装"
            ;;
    esac
}

prepare_sudo() {
    RUN_SUDO=0

    if [ ! -w "${MACOS_PATH}" ] || [ ! -w "${APP_EXECUTABLE_PATH}" ]; then
        RUN_SUDO=1
        info "Administrator permission required / 需要管理员权限，准备申请 sudo..."
        sudo -v
    fi
}

quit_wechat() {
    info "Quit WeChat / 退出微信..."

    osascript -e 'tell application "WeChat" to quit' >/dev/null 2>&1 || true
    sleep 1

    pkill -x WeChat >/dev/null 2>&1 || true

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! pgrep -x WeChat >/dev/null 2>&1; then
            ok "WeChat is not running / 微信已退出"
            return 0
        fi
        sleep 0.5
    done

    if pgrep -x WeChat >/dev/null 2>&1; then
        warn "WeChat is still running, force kill / 微信仍在运行，强制结束"
        pkill -9 -x WeChat >/dev/null 2>&1 || true
    fi
}

backup_executable() {
    info "Backup original executable / 备份微信主可执行文件..."

    if [ ! -f "${BACKUP_PATH}" ]; then
        run_cmd cp -p "${APP_EXECUTABLE_PATH}" "${BACKUP_PATH}"
        ok "Backup created / 已创建备份: ${BACKUP_PATH}"
    else
        ok "Backup already exists / 备份已存在: ${BACKUP_PATH}"
    fi
}

restore_clean_executable() {
    info "Restore clean executable from backup / 从备份恢复干净主程序..."

    [ -f "${BACKUP_PATH}" ] || die "Backup not found / 备份不存在: ${BACKUP_PATH}"

    run_cmd cp -p "${BACKUP_PATH}" "${APP_EXECUTABLE_PATH}"
    run_cmd chmod +x "${APP_EXECUTABLE_PATH}"

    ok "Executable restored / 主程序已恢复为干净版本"
}

copy_framework() {
    info "Copy plugin framework / 拷贝插件 framework..."

    run_cmd rm -rf "${FRAMEWORK_DST_PATH}"
    run_cmd ditto "${PLUGIN_SRC_PATH}" "${FRAMEWORK_DST_PATH}"

    run_cmd chmod +x "${FRAMEWORK_DST_PATH}/${FRAMEWORK_NAME}" || true

    info "Remove quarantine attribute / 移除 quarantine 属性..."
    run_cmd xattr -rd com.apple.quarantine "${FRAMEWORK_DST_PATH}" >/dev/null 2>&1 || true
    run_cmd xattr -rd com.apple.quarantine "${APP_PATH}" >/dev/null 2>&1 || true

    ok "Framework copied / 插件 framework 已拷贝"
}

insert_framework() {
    info "Insert LC_LOAD_DYLIB / 注入 LC_LOAD_DYLIB..."
    echo "    ${LOAD_DYLIB_PATH}"

    run_cmd chmod +x "${INSERT_DYLIB_PATH}"
    run_cmd "${INSERT_DYLIB_PATH}" --all-yes "${LOAD_DYLIB_PATH}" "${BACKUP_PATH}" "${APP_EXECUTABLE_PATH}"

    run_cmd chmod +x "${APP_EXECUTABLE_PATH}"

    ok "Dylib inserted / 注入完成"
}

sign_app() {
    info "Code sign plugin framework / 签名插件 framework..."
    run_cmd codesign --force --sign - --timestamp=none "${FRAMEWORK_DST_PATH}"

    info "Code sign WeChatAppEx if exists / 如果存在则签名 WeChatAppEx..."
    APP_EX_PATH="${MACOS_PATH}/WeChatAppEx.app"

    if [ -d "${APP_EX_PATH}" ]; then
        run_cmd xattr -rd com.apple.quarantine "${APP_EX_PATH}" >/dev/null 2>&1 || true
        run_cmd codesign --force --deep --sign - --timestamp=none "${APP_EX_PATH}" || true

        WEAPP_PATH="${APP_EX_PATH}/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/Helpers/WeApp.app"
        if [ -d "${WEAPP_PATH}" ]; then
            run_cmd codesign --force --deep --sign - --timestamp=none "${WEAPP_PATH}" || true
        fi
    fi

    info "Code sign main WeChat.app / 签名主 WeChat.app..."
    run_cmd codesign --force --deep --sign - --timestamp=none "${APP_PATH}"

    ok "Code sign finished / 签名完成"
}

write_state_file() {
    info "Write install state / 写入安装状态..."

    {
        echo "framework=${FRAMEWORK_NAME}"
        echo "display_version=${MATCHED_DISPLAY_VERSION:-unknown}"
        echo "short_version=${APP_SHORT_VERSION}"
        echo "build_version=${APP_BUILD_VERSION}"
        echo "backup=${BACKUP_PATH}"
        echo "load_dylib=${LOAD_DYLIB_PATH}"
        echo "installed_at=$(date '+%Y-%m-%d %H:%M:%S')"
    } | run_cmd tee "${STATE_FILE}" >/dev/null

    ok "Install state saved / 安装状态已保存: ${STATE_FILE}"
}

verify_install() {
    info "Verify inserted dylib / 检查注入结果..."

    if otool -l "${APP_EXECUTABLE_PATH}" | grep -A3 "${FRAMEWORK_NAME}" >/dev/null 2>&1; then
        ok "LC_LOAD_DYLIB found / 已检测到 ${FRAMEWORK_NAME}"
        otool -l "${APP_EXECUTABLE_PATH}" | grep -A3 "${FRAMEWORK_NAME}" || true
    else
        die "LC_LOAD_DYLIB not found / 未检测到 ${FRAMEWORK_NAME}，注入可能失败"
    fi

    echo ""
    info "Verify code signature / 检查签名..."

    if codesign -vvv --deep --strict "${APP_PATH}" >/dev/null 2>&1; then
        ok "Code signature verified / 签名验证通过"
    else
        warn "Code signature verification failed, but app may still run for debugging / 签名验证未完全通过，但调试运行不一定受影响"
    fi
}

print_done() {
    echo ""
    echo "=============================="
    echo "✅ ${FRAMEWORK_NAME} installed successfully"
    echo "✅ ${FRAMEWORK_NAME} 安装完成"
    echo "=============================="
    echo ""
    echo "Run WeChat and watch log / 启动微信并查看日志："
    echo "  rm -f ${LOG_PATH}"
    echo "  open -a WeChat"
    echo "  tail -f ${LOG_PATH}"
    echo ""
    echo "Uninstall / 卸载："
    echo "  ${SCRIPT_DIR}/uninstall.sh"
    echo ""
}

echo "=============================="
echo " Install ${FRAMEWORK_NAME}"
echo "=============================="
echo "APP_PATH=${APP_PATH}"
echo "PLUGIN_SRC_PATH=${PLUGIN_SRC_PATH}"
echo "FRAMEWORK_DST_PATH=${FRAMEWORK_DST_PATH}"
echo "INSERT_DYLIB_PATH=${INSERT_DYLIB_PATH}"
echo "SUPPORTED_FILE=${SUPPORTED_FILE}"
echo "LOAD_DYLIB_PATH=${LOAD_DYLIB_PATH}"
echo ""

check_basic_files
check_supported_version
prepare_sudo
quit_wechat
backup_executable
restore_clean_executable
copy_framework
insert_framework
sign_app
write_state_file
verify_install
print_done