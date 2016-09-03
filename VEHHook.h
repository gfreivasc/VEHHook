#pragma once
#include <Windows.h>
#include <map>

#define TRAP_FLAG (1 << 8)

typedef std::map<DWORD, DWORD>			DWDWORD;

extern DWDWORD lpHooks;
extern DWDWORD lpProtection;

class VEHHook
{
	PVOID pVectoredHandle;
	static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS);
public:
	VEHHook();
	~VEHHook();
	void AddHook(LPVOID lpEntry, PVOID pHookFunction);
	void RemoveHook(LPVOID lpEntry);
};

