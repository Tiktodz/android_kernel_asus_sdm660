#!/bin/bash

KERNELDIR=$(pwd)

# Identity
CODENAME=Hayzel
KERNELNAME=TOM
VARIANT=Stable
VERSION=4-19-318

TG_TOPIC=0
BOT_BUILD_URL="https://api.telegram.org/bot$TG_TOKEN/sendDocument"

tg_post_build()
{
	if [ $TG_TOPIC = 1 ]
	then
	    curl -F document=@"$1" "$BOT_BUILD_URL" \
	    -F chat_id="$TG_CHAT_ID"  \
	    -F "disable_web_page_preview=true" \
	    -F "parse_mode=Markdown" \
	    -F caption="$2"
	else
	    curl -F document=@"$1" "$BOT_BUILD_URL" \
	    -F chat_id="$TG_CHAT_ID"  \
	    -F "disable_web_page_preview=true" \
	    -F "parse_mode=Markdown" \
	    -F caption="$2"
	fi
}

if ! [ -d "$KERNELDIR/ew" ]; then
mkdir -p $KERNELDIR/ew && cd $KERNELDIR/ew
wget -q https://github.com/Tiktodz/electrowizard-clang/releases/download/ElectroWizard-Clang-18.1.8-release/ElectroWizard-Clang-18.1.8.tar.gz -O "ElectroWizard-Clang-18.1.8.tar.gz"
tar -xf ElectroWizard-Clang-18.1.8.tar.gz
rm -rf ElectroWizard-Clang-18.1.8.tar.gz
cd ..
fi

## Copy this script inside the kernel directory
KERNEL_DEFCONFIG=vendor/X00TD_defconfig
ANYKERNEL3_DIR=$KERNELDIR/AnyKernel3/
TZ=Asia/Jakarta
DATE=$(date '+%Y%m%d')
BUILD_START=$(date +"%s")
FINAL_KERNEL_ZIP="$KERNELNAME-$VARIANT-$VERSION-$(date '+%Y%m%d-%H%M')"
KERVER=$(make kernelversion)

# Exporting
export PATH="$KERNELDIR/ew/bin:$PATH"
export ARCH=arm64
export SUBARCH=arm64
export KBUILD_BUILD_USER="queen"
export KBUILD_BUILD_HOST=$(source /etc/os-release && echo "${NAME}")
export KBUILD_COMPILER_STRING="$($KERNELDIR/ew/bin/clang --version | head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g' -e 's/[[:space:]]*$//')"
export LLVM=1
export LLVM_IAS=1
ClangMoreStrings="AR=llvm-ar NM=llvm-nm AS=llvm-as STRIP=llvm-strip OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf HOSTAR=llvm-ar HOSTAS=llvm-as LD_LIBRARY_PATH=$KERNELDIR/ew/lib LD=ld.lld HOSTLD=ld.lld"

# Speed up build process
MAKE="./makeparallel"

# Java
command -v java > /dev/null 2>&1

# Cleaning out
mkdir -p out
make O=out clean

# Starting compilation
make $KERNEL_DEFCONFIG O=out 2>&1 | tee -a error.log
make -j$(nproc --all) O=out \
		ARCH=$ARCH \
		SUBARCH=$ARCH \
		CC="$KERNELDIR/ew/bin/clang" \
		CROSS_COMPILE=aarch64-linux-gnu- \
		HOSTCC="$KERNELDIR/ew/bin/clang" \
		HOSTCXX="$KERNELDIR/ew/bin/clang++" ${ClangMoreStrings} 2>&1 | tee -a error.log

if ! [ -f $KERNELDIR/out/arch/arm64/boot/Image.gz-dtb ]; then
    tg_post_build "error.log" "Build Error!"
    exit 1
fi

# Anykernel3 time!!
if ! [ -d "$KERNELDIR/AnyKernel3" ]; then
git clone --depth=1 https://github.com/Tiktodz/AnyKernel3 -b 419 AnyKernel3
ls $ANYKERNEL3_DIR
cp $KERNELDIR/out/arch/arm64/boot/Image.gz-dtb $ANYKERNEL3_DIR
fi

cd $ANYKERNEL3_DIR || exit 1
zip -r9 "../$FINAL_KERNEL_ZIP" * -x .git README.md ./*placeholder .gitignore  zipsigner* *.zip
ZIP_FINAL="$FINAL_KERNEL_ZIP"
cd ..
curl -sLo zipsigner-3.0.jar https://github.com/Magisk-Modules-Repo/zipsigner/raw/master/bin/zipsigner-3.0-dexed.jar
java -jar zipsigner-3.0.jar "$ZIP_FINAL".zip "$ZIP_FINAL"-signed.zip
ZIP_FINAL="$ZIP_FINAL-signed"

BUILD_END=$(date +"%s")
DIFF=$(($BUILD_END - $BUILD_START))

tg_post_build "$ZIP_FINAL.zip" "Build completed in $(($DIFF / 60)) minute(s) and $(($DIFF % 60)) second(s)"
