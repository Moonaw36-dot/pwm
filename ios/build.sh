#!/usr/bin/env bash
# Build an unsigned Aegis IPA for iOS devices.
#
# Steps: Rust FFI static lib (aarch64-apple-ios) -> UniFFI Swift bindings ->
# AegisFFI.xcframework -> XcodeGen project -> xcodebuild -> Aegis-unsigned.ipa
#
# Usage: bash ios/build.sh   (from anywhere; macOS with Xcode required)
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: ios/build.sh must run on macOS (Xcode required); detected $(uname -s)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

IOS_TARGET="aarch64-apple-ios"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"

GEN_DIR="ios/Generated"
TMP_DIR="${GEN_DIR}/tmp"
HEADERS_DIR="${GEN_DIR}/headers"
XCFRAMEWORK="${GEN_DIR}/AegisFFI.xcframework"
BUILD_DIR="ios/build"
IPA_DIR="${BUILD_DIR}/ipa"
IPA_PATH="${BUILD_DIR}/Aegis-unsigned.ipa"
HOST_DYLIB="target/release/libaegis_ffi.dylib"
DEVICE_LIB="target/${IOS_TARGET}/release/libaegis_ffi.a"

step() { printf '\n==> %s\n' "$*"; }

step "Ensuring Rust target ${IOS_TARGET}"
rustup target add "${IOS_TARGET}"

step "Building host dylib for binding generation"
cargo build -p aegis-ffi --release
[[ -f "${HOST_DYLIB}" ]] || { echo "error: ${HOST_DYLIB} not found" >&2; exit 1; }

step "Generating Swift bindings"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"
cargo run -p aegis-ffi --features cli --bin uniffi-bindgen -- \
    generate --library "${HOST_DYLIB}" --language swift --out-dir "${TMP_DIR}"
for f in aegis_ffi.swift aegis_ffiFFI.h aegis_ffiFFI.modulemap; do
    [[ -f "${TMP_DIR}/${f}" ]] || { echo "error: expected ${TMP_DIR}/${f} from uniffi-bindgen" >&2; exit 1; }
done

step "Building device static library (${IOS_TARGET}, iOS ${IPHONEOS_DEPLOYMENT_TARGET})"
cargo build -p aegis-ffi --release --target "${IOS_TARGET}"
[[ -f "${DEVICE_LIB}" ]] || { echo "error: ${DEVICE_LIB} not found" >&2; exit 1; }

step "Assembling headers and Swift sources"
rm -rf "${HEADERS_DIR}"
mkdir -p "${HEADERS_DIR}"
cp "${TMP_DIR}/aegis_ffiFFI.h" "${HEADERS_DIR}/aegis_ffiFFI.h"
cp "${TMP_DIR}/aegis_ffiFFI.modulemap" "${HEADERS_DIR}/module.modulemap"
mv -f "${TMP_DIR}/aegis_ffi.swift" "${GEN_DIR}/aegis_ffi.swift"
rm -rf "${TMP_DIR}"

step "Creating ${XCFRAMEWORK}"
rm -rf "${XCFRAMEWORK}"
xcodebuild -create-xcframework \
    -library "${DEVICE_LIB}" \
    -headers "${HEADERS_DIR}" \
    -output "${XCFRAMEWORK}"

step "Generating Xcode project with XcodeGen"
if ! command -v xcodegen >/dev/null 2>&1; then
    brew list xcodegen >/dev/null 2>&1 || brew install xcodegen
fi
(cd ios && xcodegen generate --spec project.yml)

step "Building Aegis.app (unsigned)"
rm -rf "${IPA_DIR}" "${IPA_PATH}"
mkdir -p "${BUILD_DIR}"
LOG="${BUILD_DIR}/xcodebuild.log"
xcodebuild_args=(
    -project ios/Aegis.xcodeproj
    -scheme Aegis
    -configuration Release
    -sdk iphoneos
    -destination 'generic/platform=iOS'
    -derivedDataPath "${BUILD_DIR}"
    CODE_SIGNING_ALLOWED=NO
    CODE_SIGNING_REQUIRED=NO
    CODE_SIGN_IDENTITY=""
    build
)
if command -v xcbeautify >/dev/null 2>&1; then
    xcodebuild "${xcodebuild_args[@]}" 2>&1 | tee "${LOG}" | xcbeautify
else
    xcodebuild "${xcodebuild_args[@]}" 2>&1 | tee "${LOG}"
fi

step "Packaging IPA"
APP_PATH="${BUILD_DIR}/Build/Products/Release-iphoneos/Aegis.app"
[[ -d "${APP_PATH}" ]] || { echo "error: ${APP_PATH} not found; see ${LOG}" >&2; exit 1; }
APPEX_PATH="${APP_PATH}/PlugIns/AegisAutoFill.appex"
[[ -d "${APPEX_PATH}" ]] || { echo "error: ${APPEX_PATH} not found; see ${LOG}" >&2; exit 1; }

# Xcode signing is off, so nothing embedded the entitlements. Fake-sign with
# ldid so SideStore/AltStore can read which capabilities (App Group, AutoFill)
# to request when they re-sign with your Apple ID. Extension first, then app.
step "Embedding entitlements with ldid"
if ! command -v ldid >/dev/null 2>&1; then
    brew list ldid >/dev/null 2>&1 || brew install ldid
fi
ldid -S"ios/AutoFill/AegisAutoFill.entitlements" "${APPEX_PATH}/AegisAutoFill"
ldid -S"ios/Aegis/Aegis.entitlements" "${APP_PATH}/Aegis"
ldid -e "${APP_PATH}/Aegis"

mkdir -p "${IPA_DIR}/Payload"
cp -R "${APP_PATH}" "${IPA_DIR}/Payload/"
(cd "${IPA_DIR}" && zip -qry ../Aegis-unsigned.ipa Payload)

echo
echo "Unsigned IPA: ${REPO_ROOT}/${IPA_PATH}"
