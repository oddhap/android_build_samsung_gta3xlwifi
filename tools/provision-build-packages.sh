#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y qemu-guest-agent git git-lfs curl wget rsync ca-certificates build-essential bc bison flex ccache clang lld g++-multilib gcc-multilib libssl-dev libncurses5 libncurses5-dev libelf-dev zlib1g-dev libc6-dev-i386 lib32z1-dev lib32ncurses-dev libgl1-mesa-dev libxml2-utils xsltproc unzip zip lz4 xz-utils python3 python-is-python3 openjdk-11-jdk fontconfig jq ripgrep adb android-sdk-libsparse-utils device-tree-compiler tmux
systemctl enable --now qemu-guest-agent
sudo -u builder ccache -M 40G
touch /srv/android/PROVISIONED
