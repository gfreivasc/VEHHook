#pragma once
#include <Windows.h>
#include <map>

typedef void(*PVFUNC_CALL)(PCONTEXT);
typedef std::map<LPVOID, PVFUNC_CALL>	DWHOOK;
typedef std::map<LPVOID, BYTE>			DWBYTE;

extern DWHOOK dwHooks;

class VEHHook
{
	PVOID pVectoredHandle;
	DWBYTE dwOriginalInstruction;
	static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS);
public:
	VEHHook();
	~VEHHook();
	void AddHook(LPVOID lpEntry, PVOID pHookFunction);
	void RemoveHook(LPVOID lpEntry);
};

