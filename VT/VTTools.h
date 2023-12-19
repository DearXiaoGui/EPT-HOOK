#pragma once
#include <ntifs.h>

struct _VMX_MAMAGER_PAGE_ENTRY;
union _VMX_EPTP;

typedef struct _VMXCPU
{
	ULONG cpuNumber;
	ULONG isSuccessVmOn;
	PVOID VmonMemory;
	PHYSICAL_ADDRESS VmOnPhy;

	PVOID VmCsMemory;
	PHYSICAL_ADDRESS VmCsPhy;

	PVOID VmHostStackTop; //Õ»¶¥
	PVOID VmHostStackBase; //Õ»µ×

	PVOID VmMsrBitMap;
	PHYSICAL_ADDRESS VmMsrBitMapPhy;
	
	struct _VMX_MAMAGER_PAGE_ENTRY * eptVmx;
	union _VMX_EPTP * eptp;
}VMXCPU, *PVMXCPU;

BOOLEAN VmxIsBIOSStartVT();

BOOLEAN VmxIsCpuIdSuportVT();

BOOLEAN VmxIsCr4EnableVT();

PVMXCPU VmxGetCurrentEntry();

ULONG64 VmxAdjustMsrValue(ULONG64 Value, ULONG64 msr);

BOOLEAN VmxIsControlTure();

ULONG64 VmxReadField(ULONG64 idField);

BOOLEAN VmxSetReadMsrBitMap(PUCHAR bitMap, ULONG64 msr, BOOLEAN isEnable);

BOOLEAN VmxSetWriteMsrBitMap(PUCHAR bitMap, ULONG64 msr, BOOLEAN isEnable);

VOID VmxSetMTF(BOOLEAN isOpen);