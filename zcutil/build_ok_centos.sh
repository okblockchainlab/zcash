#1
./build_ok_centos_in.sh

#2
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar xzvf LATEST.tar.gz
cd libsodium-stable
./configure --disable-pie
make
cp -f ./src/libsodium/.libs/libsodium.a ../../depends/x86_64-unknown-linux-gnu/lib/libsodium.a

#3
cd ../../src
rm -f zcash-cli-ok.so
rm -f bitcoin-cli-ok.o
make -f Makefile_src_centos