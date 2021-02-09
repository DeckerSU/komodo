## MacOS cross-compile

This branch `macos-cross-compile` allows OSX cross-build under Ubuntu / Debian, builder for `darwin` changed from gcc/g++ to clang/clang++ (using same version of
native_cctools as in bitcoin repo).

### Steps to build (Mac OS X, cross-compile)

- read following bitcoin docs: [depends](https://github.com/bitcoin/bitcoin/blob/master/depends/README.md), [macdeploy](https://github.com/bitcoin/bitcoin/blob/master/contrib/macdeploy/README.md)

```
sudo apt-get install curl librsvg2-bin libtiff-tools bsdmainutils cmake imagemagick libcap-dev libz-dev libbz2-dev python3-setuptools libtinfo5 xorriso
cd komodo
mkdir -p ${PWD}/depends/SDKs
tar -C ${PWD}/depends/SDKs -xf ${HOME}/Xcode-11.3.1-11C505-extracted-SDK-with-libcxx-headers.tar.gz
make -C ${PWD}/depends v=1 NO_QT=1 NO_PROTON=1 HOST=x86_64-apple-darwin18 DARWIN_SDK_PATH=${PWD}/depends/SDKs/Xcode-11.3.1-11C505-extracted-SDK-with-libcxx-headers -j$(nproc --all)
./autogen.sh
# ./configure --prefix=$(pwd)/depends/x86_64-apple-darwin18 --disable-tests --disable-bench --with-gui=no
CONFIG_SITE="$PWD/depends/x86_64-apple-darwin18/share/config.site" ./configure --disable-tests --disable-bench --with-gui=no
make V=1 -j$(nproc --all)
```

### Steps to build (Mac OS X, native)

```
cd komodo
# seems clang on native darwin doesn't support -fopenmp compiler flag (MULTICORE=1 for libsnark)
sed -i.old -e 's|\(CURVE=ALT_BN128[ \t]*MULTICORE=\)\([0-9]\{1,\}\)|\10|' ./depends/packages/libsnark.mk
make -C ${PWD}/depends v=1 NO_QT=1 NO_PROTON=1 HOST=x86_64-apple-darwin18 -j$(nproc --all)
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-apple-darwin18/share/config.site" ./configure --disable-tests --disable-bench --with-gui=no
make V=1 -j$(nproc --all)
```

### Steps to build (Windows x64)

```
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git python python-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils automake curl cmake mingw-w64 libsodium-dev libevent-dev
sudo update-alternatives --config x86_64-w64-mingw32-gcc
# (configure to use POSIX variant)
sudo update-alternatives --config x86_64-w64-mingw32-g++
# (configure to use POSIX variant)
cd komodo
make -C ${PWD}/depends V=1 NO_QT=1 HOST=x86_64-w64-mingw32 -j$(nproc) -j$(nproc --all)
./autogen.sh
# CXXFLAGS="-DPTW32_STATIC_LIB -DCURL_STATICLIB -DCURVE_ALT_BN128 -fopenmp -pthread"
# ./configure --prefix=$(pwd)/depends/x86_64-w64-mingw32 --disable-tests --disable-bench --with-gui=no
CONFIG_SITE="$PWD/depends/x86_64-w64-mingw32/share/config.site" CXXFLAGS="-DCURL_STATICLIB" ./configure --disable-tests --disable-bench --with-gui=no
make V=1 -j$(nproc --all)

```

### Steps to build (Linux x64)

```
# x86_64-unknown-linux-gnu (x86_64-pc-linux-gnu alias is not supported, use unknown, instead of pc)
cd komodo
make -C ${PWD}/depends V=1 NO_QT=1 HOST=x86_64-unknown-linux-gnu -j$(nproc) -j$(nproc --all)
./autogen.sh
# CXXFLAGS="-DPTW32_STATIC_LIB -DCURL_STATICLIB -DCURVE_ALT_BN128 -fopenmp -pthread"
# ./configure --prefix=$(pwd)/depends/x86_64-unknown-linux-gnu --disable-tests --disable-bench --with-gui=no
CONFIG_SITE="$PWD/depends/x86_64-unknown-linux-gnu/share/config.site" CXXFLAGS="-DCURL_STATICLIB" ./configure --disable-tests --disable-bench -with-gui=no
make V=1 -j$(nproc --all)
```

### Useful links

- https://en.wikipedia.org/wiki/Darwin_(operating_system) (Darwin 18 -> macOS Mojave iOS 12)