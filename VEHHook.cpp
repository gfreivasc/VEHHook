#include "VEHHook.h"

std::vector<VEHHook::HookCtx> VEHHook::m_HookTargets;
std::mutex VEHHook::m_TargetMutex;

VEHHook::VEHHook() : m_Hooked(false)
{
	try
	{
		m_pVectoredHandle = AddVectoredExceptionHandler(1, &VEHHook::VectoredHandler);

		if (m_pVectoredHandle == NULL)
			throw std::runtime_error("Could not add Vectored Exception Handler");
	}
	catch (const std::runtime_error& e)
	{
		throw e;
	}
}


VEHHook::~VEHHook()
{
	if (m_Hooked) RemoveAll();
	RemoveVectoredExceptionHandler(m_pVectoredHandle);
}

bool VEHHook::AddHook(PBYTE pEntry, PBYTE pHookFunction)
{
	HookCtx Ctx(pEntry, pHookFunction);
	
	std::lock_guard<std::mutex> Lock(m_TargetMutex);

	DWORD dwOld;
	VirtualProtect(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	Ctx.m_StorageByte = *Ctx.m_Src;
	*Ctx.m_Src = 0xCC;
	VirtualProtect(Ctx.m_Src, 1, dwOld, &dwOld);

	m_HookTargets.push_back(Ctx);
	if (!m_Hooked) m_Hooked = true;
	return true;
}

void VEHHook::RemoveHook(PBYTE pEntry)
{
	std::lock_guard<std::mutex> Lock(m_TargetMutex);

	DWORD dwOld;
	for (HookCtx &Ctx : m_HookTargets)
	{
		if (Ctx.m_Src != pEntry) continue;

		VirtualProtect(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE, &dwOld);
		*Ctx.m_Src = Ctx.m_StorageByte;
		VirtualProtect(Ctx.m_Src, 1, dwOld, &dwOld);

		m_HookTargets.erase(
			std::remove(m_HookTargets.begin(), m_HookTargets.end(), Ctx),
			m_HookTargets.end()
		);

		if (m_HookTargets.size() == 0)
			m_Hooked = false;
	}
}

void VEHHook::RemoveAll()
{
	std::lock_guard<std::mutex> Lock(m_TargetMutex);
	
	DWORD dwOld;
	for (HookCtx &Ctx : m_HookTargets)
	{
		VirtualProtect(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE, &dwOld);
		*Ctx.m_Src = Ctx.m_StorageByte;
		VirtualProtect(Ctx.m_Src, 1, dwOld, &dwOld);
	}

	m_HookTargets.clear();
	m_Hooked = false;
}

LONG CALLBACK VEHHook::VectoredHandler(_In_ PEXCEPTION_POINTERS pExceptionInfo)
{
#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif
	std::lock_guard<std::mutex> Lock(m_TargetMutex);

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		DWORD dwOld;
		for (HookCtx& Ctx : m_HookTargets)
		{
			if (pExceptionInfo->ContextRecord->XIP != (DWORD_PTR)Ctx.m_Src)
				continue;

			VirtualProtect(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE, &dwOld);
			*Ctx.m_Src = Ctx.m_StorageByte;
			VirtualProtect(Ctx.m_Src, 1, dwOld, &dwOld);

			pExceptionInfo->ContextRecord->XIP = (DWORD_PTR)Ctx.m_Dest;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
