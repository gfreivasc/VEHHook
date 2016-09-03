#include "VEHHook.h"

DWHOOK dwHooks;

VEHHook::VEHHook()
{
	try
	{
		this->pVectoredHandle = AddVectoredExceptionHandler(1, &VEHHook::VectoredHandler);

		if (this->pVectoredHandle == NULL)
			throw std::runtime_error("Could not add Vectored Exception Handler");
	}
	catch (const std::runtime_error& e)
	{
		throw e;
	}
}


VEHHook::~VEHHook()
{
	RemoveVectoredExceptionHandler(this->pVectoredHandle);
}

void VEHHook::AddHook(LPVOID lpEntry, PVOID pHookFunction)
{
	dwHooks[lpEntry] = (PVFUNC_CALL)pHookFunction;
	this->dwOriginalInstruction[lpEntry] = *(PBYTE)lpEntry;
	DWORD dwOld;
	VirtualProtect(lpEntry, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	*(PBYTE)lpEntry = 0xCC;
	VirtualProtect(lpEntry, 1, dwOld, &dwOld);
}

void VEHHook::RemoveHook(LPVOID lpEntry)
{
	DWORD dwOld;
	VirtualProtect(lpEntry, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	*(PBYTE)lpEntry = this->dwOriginalInstruction[lpEntry];
	VirtualProtect(lpEntry, 1, dwOld, &dwOld);
	dwHooks[lpEntry] = NULL;
}

LONG CALLBACK VEHHook::VectoredHandler(_In_ PEXCEPTION_POINTERS pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		LPVOID lpCall;
#ifdef _WIN64
		lpCall = (LPVOID)pExceptionInfo->ContextRecord->Rip;
#else
		lpCall = (LPVOID)pExceptionInfo->ContextRecord->Eip;
#endif
		dwHooks[lpCall](pExceptionInfo->ContextRecord);
	}

	pExceptionInfo->ContextRecord->EFlags |= 0x100;
	return EXCEPTION_CONTINUE_EXECUTION;
}
