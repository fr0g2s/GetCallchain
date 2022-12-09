#include <stdio.h>

void D()
{
	puts("HI");	
}

void recursive(int x)
{
	printf("%d\n", x);
	if(x >= 100) D();
	else recursive(x * 2);
}

int main(void)
{
	recursive(1);
	return 0;
}
