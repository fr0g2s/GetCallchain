#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void C(char arg[])
{
  char buf[0x100];
  if(arg[2] == 'G' && arg[3] == 'G') {
    memcpy(buf, arg, 0x200);
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
  if(argc != 2) {
    fprintf(stderr, "USAGE: ./%s arg1 \n", argv[0]);
    return 1; 
  }
  A(argv[1]);

  return 0;
}
