#include <cstdio>
#include "VEHHook.h"

void hello(int d)
{
	printf("Hello n%d\n", d);
}

void goodbye(int d)
{
	printf("Good bye n%d\n", d);
}

int main() {
	VEHHook *Hook = new VEHHook();

	hello(1);
	Hook->AddHook((PBYTE)&hello, (PBYTE)&goodbye);
	hello(2);
	Hook->RemoveHook((PBYTE)&hello);
	hello(3);

	delete Hook;
	system("Pause");
	return 0;
}