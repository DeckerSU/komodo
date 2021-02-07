## MacOS cross-compile

This branch `macos-cross-compile` allows OSX cross-build under Ubuntu / Debian, builder for darwing changed from gcc/g++ to clang/clang++ (using same version of
native_cctools as in bitcoin repo).

### Steps to build

- read following bitcoin docs: [depends](https://github.com/bitcoin/bitcoin/blob/master/depends/README.md), [macdeploy](https://github.com/bitcoin/bitcoin/blob/master/contrib/macdeploy/README.md)

```
sudo apt-get install curl librsvg2-bin libtiff-tools bsdmainutils cmake imagemagick libcap-dev libz-dev libbz2-dev python3-setuptools libtinfo5 xorriso
cd komodo
mkdir -p ${PWD}/depends/SDKs
tar -C ${PWD}/depends/SDKs -xf ${HOME}/Xcode-11.3.1-11C505-extracted-SDK-with-libcxx-headers.tar.gz
make -C ${PWD}/depends v=1 NO_QT=1 NO_PROTON=1 HOST=x86_64-apple-darwin18 DARWIN_SDK_PATH=${PWD}/depends/SDKs/Xcode-11.3.1-11C505-extracted-SDK-with-libcxx-headers -j$(nproc --all)
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-apple-darwin18/share/config.site" ./configure --disable-tests --disable-bench --with-gui=no
make V=1 -j$(nproc --all)
```