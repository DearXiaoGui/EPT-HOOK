#pragma once
#include <ntifs.h>

#define __EPT_HOOK_MAX (0x20)


typedef struct _EptHookContext 
{
	LIST_ENTRY listEntry;

	PUCHAR HookPageStart;
	PUCHAR NewPageStart;

	ULONG64 HookPageNumber;
	ULONG64 NewPageNumber;

	ULONG64 HookAddress[__EPT_HOOK_MAX];
	ULONG64 NewAddress[__EPT_HOOK_MAX];
	ULONG HookCodeLen[__EPT_HOOK_MAX];

	ULONG HookCount;

	BOOLEAN isKernelHook;

	ULONG64 KernelCr3;
	ULONG64 UserCr3;
	
	
	BOOLEAN isHookSuccess;

	ULONG64 HookHpaPageNumber;
}EptHookContext,*PEptHookContext;

PEptHookContext VmxEptGetHookContext(ULONG64 HookAddress);

BOOLEAN VmxEptHookPage(ULONG64 HookAddress, ULONG64 newAddress);