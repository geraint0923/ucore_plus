source ~/.profile
make ARCH=arm BOARD=goldfishv7 defconfig
make sfsimg
make kernel
./uCore_run
