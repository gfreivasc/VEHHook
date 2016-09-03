#pragma once
#include <Windows.h>
#include <vector>
#include <mutex>
#include <algorithm>

#define TRAP_FLAG (1 << 8)

class VEHHook
{
public:
	VEHHook();
	~VEHHook();
	bool AddHook(PBYTE pEntry, PBYTE pHookFunction);
	void RemoveHook(PBYTE pEntry);
	void RemoveAll();
protected:
	struct HookCtx
	{
		PBYTE m_Src;
		PBYTE m_Dest;
		BYTE  m_StorageByte;

		HookCtx(PBYTE src, PBYTE dest)
		{
			m_Src = src;
			m_Dest = dest;
		}

		friend bool operator==(const HookCtx& Ctx1, const HookCtx& Ctx2)
		{
			return Ctx1.m_Dest == Ctx2.m_Dest && Ctx1.m_Src == Ctx2.m_Src;
		}
	};
private:
	PVOID m_pVectoredHandle;
	static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS);
	static std::vector<HookCtx> m_HookTargets;
	static std::mutex m_TargetMutex;
	bool m_Hooked;
};

