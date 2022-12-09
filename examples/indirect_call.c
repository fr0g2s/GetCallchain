// 간접호출 테스트
#include <stdio.h>

void A(void) { puts("A"); }

int main(void) {
	void (*fp)() = A;
	fp();
}
