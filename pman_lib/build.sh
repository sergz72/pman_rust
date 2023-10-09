HEADERPATH="bindings/pman_libFFI.h"
TARGETDIR="target"
OUTDIR="../pman"
RELDIR="release"
NAME="pman_lib"
STATIC_LIB_NAME="lib${NAME}.a"
NEW_HEADER_DIR="bindings/include"

export PATH=$PATH:/Users/serhiizashchelkin/Library/Android/sdk/ndk/26.0.10792818/toolchains/llvm/prebuilt/darwin-x86_64/bin

cargo build --target aarch64-apple-darwin --release
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release
cargo build --target aarch64-linux-android --release

mkdir -p "${NEW_HEADER_DIR}"
cp "${HEADERPATH}" "${NEW_HEADER_DIR}/"
cp "bindings/pman_libFFI.modulemap" "${NEW_HEADER_DIR}/module.modulemap"

rm -rf "${OUTDIR}/${NAME}_framework.xcframework"

xcodebuild -create-xcframework \
    -library "${TARGETDIR}/aarch64-apple-darwin/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/aarch64-apple-ios/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/aarch64-apple-ios-sim/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -output "${OUTDIR}/${NAME}_framework.xcframework"

cp bindings/uniffi/pman_lib/pman_lib.kt ../pman_android/app/src/main/java/uniffi/pman_lib 
cp target/aarch64-linux-android/release/libpman_lib.so ../pman_android/app/src/main/jniLibs/arm64-v8a/libuniffi_pman_lib.so
