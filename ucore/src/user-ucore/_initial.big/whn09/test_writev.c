#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/uio.h>

int main(int argc,char **argv)
{
	int len;
	int fd;
	fd = open("test_writev.txt", O_RDWR);
    char part1[] = "This is iov";
    char part2[] = " and ";
    char part3[] = " writev test";

    struct iovec iov[3];
    iov[0].iov_base = part1;
    iov[0].iov_len = strlen(part1);
    iov[1].iov_base = part2;
    iov[1].iov_len = strlen(part2);
    iov[2].iov_base = part3;
    iov[2].iov_len = strlen(part3);
    len = writev(fd,iov,3);
    printf("%d\n", len);

    return 0;
}
