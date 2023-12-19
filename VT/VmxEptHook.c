#include "VmxEptHook.h"
#include <intrin.h>
#include "vmxs.h"
#include "AsmCode.h"
#include "VTDefine.h"

EptHookContext gEptHookContext = {0};


VOID KeGenericCallDpc(__in PKDEFERRED_ROUTINE Routine, __in_opt PVOID Context);

VOID KeSignalCallDpcDone(__in PVOID SystemArgument1);

LOGICAL KeSignalCallDpcSynchronize(__in PVOID SystemArgument2);


ULONG GetHookLen(ULONG64 HookAddress, ULONG minLen,BOOLEAN isX64)
{
	ULONG len = 0;
	ULONG offset = 0;

	if (isX64)
	{
		
		while (len < minLen)
		{
			offset = insn_len_x86_64(HookAddress + len);

			len += offset;
		}
		
	}
	else 
	{
		while (len < minLen)
		{
			offset = insn_len_x86_32(HookAddress + len);

			len += offset;
		}
	}

	return len;
}

ULONG64 GetCurrentProcessUserCr3()
{  
	static ULONG offset = 0;
	if (!offset)
	{
		RTL_OSVERSIONINFOEXW version = {0};
		RtlGetVersion(&version);

		if (version.dwBuildNumber < 1809)
		{
			offset = 0;
		}
		else if (version.dwBuildNumber == 1809 || version.dwBuildNumber == 1803)
		{
			offset = 0x278;
		}
		else if (version.dwBuildNumber == 1909 || version.dwBuildNumber == 1903)
		{
			offset = 0x280;
		}
		else 
		{
			offset = 0x388;
		}
	}

	PEPROCESS Process = IoGetCurrentProcess();

	ULONG64 userCr3 = 1;
	if (offset)
	{
		userCr3 = *(PULONG64)((PUCHAR)Process + offset);
	}

	return userCr3;
}

VOID VmxEptHookContextInit(PEptHookContext context)
{
	memset(context, 0, sizeof(EptHookContext));

	InitializeListHead(&context->listEntry);

	context->KernelCr3 = __readcr3() & (~0xfffull);

	context->UserCr3 = GetCurrentProcessUserCr3();
}

PEptHookContext VmxEptGetHookContext(ULONG64 HookAddress)
{
	ULONG64 pageStart = (HookAddress >> 12) << 12;

	PLIST_ENTRY list = &gEptHookContext.listEntry;

	PLIST_ENTRY next = list;
	
	PEptHookContext retContext = NULL;

	ULONG64 kernelCr3 = __readcr3() & (~0xfffull);

	ULONG64 userCr3 = GetCurrentProcessUserCr3();

	do 
	{
		PEptHookContext temp = (PEptHookContext)next;

		if (temp->HookPageStart == pageStart)
		{
			if (temp->isKernelHook)
			{
				retContext = temp;
				break;
			}

			if ((temp->KernelCr3 == kernelCr3) || (userCr3 != 1 && userCr3 == temp->UserCr3))
			{
				retContext = temp;
				break;
			}
		}

		next = next->Flink;
	} while (list != next);

	return retContext;

}


VOID EptHookDpc(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{

	PEptHookContext context = (PEptHookContext)DeferredContext;
	
	ULONG64 codePageNumber = 0;
	
	AsmVmCallHook(_EPT_HOOK_TAG, context->KernelCr3, context->HookPageNumber, context->NewPageNumber, &codePageNumber);
	
	context->HookHpaPageNumber = codePageNumber;

	DbgPrintEx(77, 0, "[db]:hook status = %llx\r\n", codePageNumber);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

BOOLEAN VmxEptHookPage(ULONG64 HookAddress, ULONG64 newAddress)
{
	
	if (!MmIsAddressValid(HookAddress) || !MmIsAddressValid(newAddress))
	{
		return FALSE;
	}

	if (gEptHookContext.listEntry.Flink == 0)
	{
		InitializeListHead(&gEptHookContext.listEntry);
	}

	PEptHookContext context = VmxEptGetHookContext(HookAddress);

	ULONG64 pageStart = (HookAddress >> 12) << 12;

	if (!context)
	{
		context = ExAllocatePool(NonPagedPool, sizeof(EptHookContext));

		if (!context) return FALSE;

		VmxEptHookContextInit(context);

		context->HookPageStart = pageStart;
	}


	context->HookAddress[context->HookCount] = HookAddress;

	context->NewAddress[context->HookCount] = newAddress;

	if (!context->NewPageStart)
	{
		context->NewPageStart = ExAllocatePool(NonPagedPool, PAGE_SIZE);

		if (!context->NewPageStart)
		{
			ExFreePool(context);
			return FALSE;
		}
	}


	//复制样本
	memcpy(context->NewPageStart, pageStart, PAGE_SIZE);

	//获取HOOK 地址
	ULONG64 hookOffset = HookAddress - pageStart;

	PUCHAR hookPos = context->NewPageStart + hookOffset;

	//构建HOOK
	char bufHook[] =
	{
		0x68,0x78,0x56,0x34,0x12,
		0xC7,0x44,0x24,0x04,0x78,0x56,0x34,0x12,
		0xC3
	};

	LARGE_INTEGER inHookAddress = {0};
	inHookAddress.QuadPart = newAddress;
	*(PULONG)&bufHook[1] = inHookAddress.LowPart;
	*(PULONG)&bufHook[9] = inHookAddress.HighPart;

	memcpy(hookPos, bufHook, sizeof(bufHook));

	ULONG len = GetHookLen(HookAddress, sizeof(bufHook), TRUE);

	context->HookCodeLen[context->HookCount] = len;

	context->HookCount++;

	context->isKernelHook =  ((HookAddress >> 48) & 0xFFFF) == 0xFFFF;

	context->isHookSuccess = TRUE;


	context->HookPageNumber = MmGetPhysicalAddress(HookAddress).QuadPart / PAGE_SIZE;
	context->NewPageNumber = MmGetPhysicalAddress(context->NewPageStart).QuadPart / PAGE_SIZE;

	InsertTailList(&gEptHookContext.listEntry, &context->listEntry);

	//VmCall 进入到VT 挂钩

	KeGenericCallDpc(EptHookDpc, context);

	return context->isHookSuccess;
}