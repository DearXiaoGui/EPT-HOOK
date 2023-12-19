#include <ntifs.h>
#include "VTTools.h"
#include "vmx.h"
#include "vmxs.h"
#include "VmxEptHook.h"


EXTERN_C ULONG64 JmpOpenProcessRet = 0;

VOID KeGenericCallDpc(__in PKDEFERRED_ROUTINE Routine,__in_opt PVOID Context);

VOID KeSignalCallDpcDone(__in PVOID SystemArgument1);

LOGICAL KeSignalCallDpcSynchronize(__in PVOID SystemArgument2);

VOID StartVT(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	do 
	{
		if (!VmxIsCpuIdSuportVT())
		{
			DbgPrintEx(77, 0, "[db]:cpuid not support vt number = %d\r\n", KeGetCurrentProcessorNumberEx(NULL));
			break;
		}

		if (!VmxIsBIOSStartVT())
		{
			DbgPrintEx(77, 0, "[db]:bios disable vt lock vt number = %d\r\n", KeGetCurrentProcessorNumberEx(NULL));
			break;
		}

		if (!VmxIsCr4EnableVT())
		{
			DbgPrintEx(77, 0, "[db]:vt 已存在 number = %d \r\n", KeGetCurrentProcessorNumberEx(NULL));
			break;
		}

		if (VMXInit(DeferredContext))
		{
			DbgPrintEx(77, 0, "[db]:vt number = %d\r\n", KeGetCurrentProcessorNumberEx(NULL));
		}
	
	} while (0);
	
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}


BOOLEAN UtilForEachProcessor(BOOLEAN(*callback_routine)(void *), void *context)
{

	const ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	BOOLEAN status = TRUE;

	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) {
		PROCESSOR_NUMBER processor_number = { 0 };

		if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processor_index, &processor_number)))
		{
			return FALSE;
		}

	

		// Switch the current processor
		GROUP_AFFINITY affinity = { 0 };
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = { 0 };
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		status = callback_routine(context);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!status)
		{
			return FALSE;
		}
	}
	return TRUE;
}



VOID CloseVT(_In_opt_ PVOID DeferredContext)
{
	VMXExitOff();
	
}

VOID EnableVT()
{
	KeGenericCallDpc(StartVT, AsmVmxExitHandler);
}

VOID DisableVT()
{

	UtilForEachProcessor(CloseVT, NULL);

	//KeGenericCallDpc(CloseVT, NULL);
	//DbgBreakPoint();
}
typedef NTSTATUS(NTAPI* NtOpenProcessProc)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

NtOpenProcessProc NtOpenProcessFunc = NULL;

NTSTATUS NTAPI MyOpenProcess( 
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	DbgPrintEx(77, 0, "EPT HOOK OpenProcess 完成\r\n");


	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	DisableVT();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	
	JmpOpenProcessRet = (ULONG64)NtOpenProcess + 0x14;


	EnableVT(); //开启VT 

	VmxEptHookPage(NtOpenProcess, AsmNtOpenProcess);  //开始 EPT HOOK
	

	pDriver->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}