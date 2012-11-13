#To compile a *.cpp file, use the command below
#To run helloworld(arm), directory 'system' and file 'bionic.ld' are required
make:all
all:
	arm-linux-androideabi-g++ helloworld.cpp -o helloworld -T bionic.ld
	arm-linux-androideabi-gcc test_write.c -o test_write -T bionic.ld
	arm-linux-androideabi-gcc test_writev.c -o test_writev -T bionic.ld

