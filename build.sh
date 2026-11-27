#!/bin/bash

if [ ! -d "./build" ]; then
    mkdir ./build
else
    rm -rf ./build
    mkdir ./build
fi

printf "Execution options: %s\n" "$1"
case "$1" in
    "driver")
        cd ./driver || exit 1
        make
        mv -- ./*.ko ../build/
        make clean
        # 用于 PC 的 GNU/Linux 可能会需要密钥签名
        # openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=My Own Key/"
        # sudo mokutil --import MOK.der
        # Reboot --> 蓝色 MOK Manager 界面 --> Enroll MOK
        if [ -f "../tmp/MOK.der" ] && [ -f "../tmp/MOK.priv" ]; then
            cd ../tmp || exit 1
            /usr/src/linux-headers-"$(uname -r)"/scripts/sign-file sha256 MOK.priv MOK.der ../build/*.ko
        fi
        ;;
    "kernel")
        printf "No executable projects available\n"
        ;;
    "modules")
        cd ./build || exit 1
        cmake ../modules/
        # shellcheck disable=SC2154
        make -j"${nproc}"
        ;;
    "unsafety")
        cd ./build || exit 1
        cmake ../unsafety/
        # shellcheck disable=SC2154
        make -j"${nproc}"
        ;;
    "tools")
        cd ./tools || exit 1
        make -j"${nproc}"
        make clean
        ;;
    "asm")
        cd ./asm || exit 1
        as -32 -g -o start.o start.s
        ld -m elf_i386 -o start start.o
        mv ./start ../build
        rm -f start.o
        printf "Built target start\n"
        ;;
    *)
        printf "Usages: ./build.sh [driver|kernel|modules|unsafety|tools|asm]\n"
        ;;
esac
printf "Execution end\n"
