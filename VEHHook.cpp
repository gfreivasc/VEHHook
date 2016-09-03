#include "VEHHook.h"

DWDWORD lpHooks;
DWDWORD lpProtection;

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
	lpHooks[(DWORD)lpEntry] = (DWORD)pHookFunction;
	DWORD dwOld;
	VirtualProtect(lpEntry, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
	lpProtection[(DWORD)lpEntry] = dwOld;
}

void VEHHook::RemoveHook(LPVOID lpEntry)
{
	DWORD dwOld;
	VirtualProtect(lpEntry, 1, lpProtection[(DWORD)lpEntry], &dwOld);
	lpHooks[(DWORD)lpEntry] = NULL;
}

LONG CALLBACK VEHHook::VectoredHandler(_In_ PEXCEPTION_POINTERS pExceptionInfo)
{
	static DWORD lpLastRaised = NULL;
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		DWORD lpEntry;
#ifdef _WIN64
		lpEntry = pExceptionInfo->ContextRecord->Rip + 7;
#else
		lpEntry = pExceptionInfo->ContextRecord->Eip + 3;
#endif
		DWDWORD::iterator it = lpHooks.find(lpEntry);
		if (it != lpHooks.end())
		{
			lpLastRaised = lpEntry;
#ifdef _WIN64
			pExceptionInfo->ContextRecord->Rip = (DWORD64)(it->second);
#else
			pExceptionInfo->ContextRecord->Eip = it->second;
#endif
		}

		pExceptionInfo->ContextRecord->EFlags |= TRAP_FLAG;
	}
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		DWORD dwOld;
		VirtualProtect((LPVOID)lpLastRaised, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
	}
	else
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}
