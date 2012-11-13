#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
	int len;
	int fd;
	fd = open("test_write.txt", O_RDWR);

	char *buff_one = "abcdefgh";
	len = write(fd, buff_one, 256);
	printf("%d\n", len);

	char buff_two[6] = "abc";
	len = write(fd, buff_one, 256);
	printf("%d\n", len);

	buff_one = "abcdefgh";
	len = write(fd, buff_one, 2);
	printf("%d\n", len);

	buff_two[6] = "abc";
	len = write(fd, buff_one, 2);
	printf("%d\n", len);

	buff_one = "abcdefgh";
	len = write(fd, buff_one, strlen(buff_one));
	printf("%d\n", len);

	buff_two[6] = "abc";
	len = write(fd, buff_one, strlen(buff_two));
	printf("%d\n", len);

	return 0;
}
