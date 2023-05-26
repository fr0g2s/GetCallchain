#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
	char *buf = "hello";
	puts(buf);
	system("/bin/sh");
}

void C(char arg[])
{
  char buf[0x50];
  if(arg[2] == 'G' && arg[3] == 'G') {
    memcpy(buf, arg, 0x100);
  }
}

void D(){ puts("hello"); }

void B(char arg[])
{
	D();
  if(arg[1] == 'E') {
    C(arg);
  }
}

void A(char arg[])
{
  if(arg[0] == 'A') {
     B(arg);
  }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	puts("AEG me");
  char buf[0x100];
	read(0, buf, 0x100);
	A(buf);

  return 0;
}
