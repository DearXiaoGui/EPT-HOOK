#include "vmx.h"
#include "VTTools.h"
#include "VTDefine.h"
#include <intrin.h>
#include "vmxs.h"
#include "VmxEpt.h"

VOID VmxFreeMemory()
{
	PVMXCPU vmxCpu = VmxGetCurrentEntry();
	
	if (vmxCpu->isSuccessVmOn)
	{
		//进入VT
		/**
		....
		*/
		//退出VT 环境
		__vmx_off();
	}
	
	ULONG64 vcr40 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 mcr4 = __readcr4();
	mcr4 &= ~vcr40;
	__writecr4(mcr4);

	if (vmxCpu->VmonMemory)
	{
		MmFreeContiguousMemorySpecifyCache(vmxCpu->VmonMemory, PAGE_SIZE, MmCached);
		vmxCpu->VmonMemory = NULL;

	}

	if (vmxCpu->VmCsMemory)
	{
		MmFreeContiguousMemorySpecifyCache(vmxCpu->VmCsMemory, PAGE_SIZE, MmCached);
		vmxCpu->VmCsMemory = NULL;

	}

	if (vmxCpu->VmHostStackTop)
	{
		MmFreeContiguousMemorySpecifyCache(vmxCpu->VmHostStackTop, PAGE_SIZE * 36, MmCached);
		vmxCpu->VmHostStackTop = NULL;

	}

	if (vmxCpu->VmMsrBitMap)
	{
		MmFreeContiguousMemorySpecifyCache(vmxCpu->VmMsrBitMap, PAGE_SIZE, MmCached);
		vmxCpu->VmMsrBitMap = NULL;

	}

	if (vmxCpu->eptp)
	{
		ExFreePool(vmxCpu->eptp);
		vmxCpu->eptp = NULL;

	}

	//int size = sizeof(VMX_MAMAGER_PAGE_ENTRY);
	if (vmxCpu->eptVmx)
	{
		MmFreeContiguousMemorySpecifyCache(vmxCpu->eptVmx, sizeof(VMX_MAMAGER_PAGE_ENTRY), MmCached);
		vmxCpu->eptVmx = NULL;
	}
}

VOID VMXExitOff()
{
	AsmVmCall('exit');
	
	
	VmxFreeMemory();

	//DbgBreakPoint();
}

BOOLEAN VMXInitVmOn()
{

	//初始化结构
	PVMXCPU vmxCpu = VmxGetCurrentEntry();

	vmxCpu->cpuNumber = KeGetCurrentProcessorNumberEx(NULL);

	PHYSICAL_ADDRESS low, hei;
	low.QuadPart = 0;
	hei.QuadPart = MAXULONG64;
	vmxCpu->VmonMemory = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);
	memset(vmxCpu->VmonMemory, 0, PAGE_SIZE);
	vmxCpu->VmOnPhy = MmGetPhysicalAddress(vmxCpu->VmonMemory);

	//开启CR4

	ULONG64 mcr4 = __readcr4();
	ULONG64 mcr0 = __readcr0();

	ULONG64 vcr00 = __readmsr(IA32_VMX_CR0_FIXED0);
	ULONG64 vcr01 = __readmsr(IA32_VMX_CR0_FIXED1);
	ULONG64 vcr40 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 vcr41 = __readmsr(IA32_VMX_CR4_FIXED1);

	mcr0 |= vcr00;
	mcr0 &= vcr01;

	mcr4 |= vcr40;
	mcr4 &= vcr41;

	__writecr4(mcr4);
	__writecr0(mcr0);

	vmxCpu->isSuccessVmOn = 0;

	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	*(PULONG)vmxCpu->VmonMemory = (ULONG)basic;

	int error = __vmx_on(&vmxCpu->VmOnPhy.QuadPart);

	DbgPrintEx(77, 0, "[db]:%s vmx_on err = %d\r\n", __FUNCTION__, error);


	if (error)
	{
		VmxFreeMemory();

	}
	else 
	{
		vmxCpu->isSuccessVmOn = 1;
	}
	
	return error == 0;
}

void FullGdtDataItem(int index, short selector)
{
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);
	//00cf9300`0000ffff

	USHORT select = selector;
	selector &= 0xFFF8;

	ULONG64 limit = __segmentlimit(selector);
	PULONG item = (PULONG)(gdtTable.Base + selector);

	LARGE_INTEGER itemBase = { 0 };
	itemBase.LowPart = (*item & 0xFFFF0000) >> 16;
	item += 1;
	itemBase.LowPart |= (*item & 0xFF000000) | ((*item & 0xFF) << 16);

	//属性
	ULONG attr = (*item & 0x00F0FF00) >> 8;



	if (selector == 0)
	{
		attr |= 1 << 16;
	}

	__vmx_vmwrite(GUEST_ES_BASE + index * 2, itemBase.QuadPart);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, select);

}

VOID VMXInitGuestState(ULONG64 guestRip, ULONG64 GuestRsp)
{
	PVMXCPU vmxCpu = VmxGetCurrentEntry();

	FullGdtDataItem(0, AsmReadES());
	FullGdtDataItem(1, AsmReadCS());
	FullGdtDataItem(2, AsmReadSS());
	FullGdtDataItem(3, AsmReadDS());
	FullGdtDataItem(4, AsmReadFS());
	FullGdtDataItem(5, AsmReadGS());
	FullGdtDataItem(6, AsmReadLDTR());
	
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);


	ULONG trSelector = AsmReadTR();

	trSelector &= 0xFFF8;
	ULONG64 trlimit = __segmentlimit(trSelector);

	LARGE_INTEGER trBase = { 0 };

	PULONG trItem = (PULONG)(gdtTable.Base + trSelector);


	//读TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
	ULONG attr = (trItem[1] & 0x00F0FF00) >> 8;
	__vmx_vmwrite(GUEST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trlimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, attr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_MSR_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(IA32_MSR_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(IA32_MSR_EFER));

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(0x176));

	
	__vmx_vmwrite(GUEST_GDTR_BASE, gdtTable.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtTable.limit);

	//设置虚拟机第一次的返回地址与堆栈
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	__vmx_vmwrite(GUEST_RIP, guestRip);

	GdtTable idtTable = { 0 };
	__sidt(&idtTable);
	__vmx_vmwrite(GUEST_IDTR_BASE, idtTable.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtTable.limit);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_DR7,__readdr(7));

	__vmx_vmwrite(VMCS_LINK_POINTER, -1);

}

VOID VMXInitHostState(ULONG64 HostRIP)
{
	PVMXCPU vmxCpu = VmxGetCurrentEntry();


	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);


	ULONG trSelector = AsmReadTR();

	trSelector &= 0xFFF8;

	LARGE_INTEGER trBase = { 0 };

	PULONG trItem = (PULONG)(gdtTable.Base + trSelector);


	//读TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
	__vmx_vmwrite(HOST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(HOST_ES_SELECTOR, AsmReadES() & 0xfff8);
	__vmx_vmwrite(HOST_CS_SELECTOR, AsmReadCS() & 0xfff8);
	__vmx_vmwrite(HOST_SS_SELECTOR, AsmReadSS() & 0xfff8);
	__vmx_vmwrite(HOST_DS_SELECTOR, AsmReadDS() & 0xfff8);
	__vmx_vmwrite(HOST_FS_SELECTOR, AsmReadFS() & 0xfff8);
	__vmx_vmwrite(HOST_GS_SELECTOR, AsmReadGS() & 0xfff8);



	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_RSP, (ULONG64)vmxCpu->VmHostStackBase);
	__vmx_vmwrite(HOST_RIP, HostRIP);


	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(IA32_MSR_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(IA32_MSR_EFER));
	//__vmx_vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL));
	
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(0x176));
	

	//IDT GDT

	GdtTable idtTable;
	__sidt(&idtTable);

	__vmx_vmwrite(HOST_GDTR_BASE, gdtTable.Base);
	__vmx_vmwrite(HOST_IDTR_BASE, idtTable.Base);
}

VOID VMXInitEntry()
{
	ULONG64 contorlmsr = VmxIsControlTure() ? IA32_MSR_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;
	
	ULONG mark = (1 << 9) ;
	ULONG64 msrValue = VmxAdjustMsrValue(mark, contorlmsr);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, msrValue);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	
	

}


VOID VMXInitExit()
{
	ULONG64 contorlmsr = VmxIsControlTure() ? IA32_MSR_VMX_TRUE_EXIT_CTLS : IA32_MSR_VMX_EXIT_CTLS;

	ULONG mark = 0x200 | 0x8000;
	ULONG64 value = VmxAdjustMsrValue(0x200 | 0x8000, contorlmsr);
	__vmx_vmwrite(VM_EXIT_CONTROLS, value);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_INTR_INFO, 0);

	

}

VOID VMXInitControl()
{
	PVMXCPU vmxCpu = VmxGetCurrentEntry();

	ULONG64 contorlmsr = VmxIsControlTure() ? IA32_MSR_VMX_TRUE_PINBASED_CTLS : IA32_MSR_VMX_PINBASED_CTLS;
	ULONG64 Proccontorlmsr = VmxIsControlTure() ? IA32_MSR_VMX_TRUE_PROCBASED_CTLS : IA32_MSR_VMX_PROCBASED_CTLS;

	ULONG mark = 0;
	ULONG64 msrValue = VmxAdjustMsrValue(mark, contorlmsr);

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, msrValue);



	mark = CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	msrValue = VmxAdjustMsrValue(mark, Proccontorlmsr);
	
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, msrValue);


	//VmxSetReadMsrBitMap(vmxCpu->VmMsrBitMap, 0xc0000082, TRUE);

	__vmx_vmwrite(MSR_BITMAP, vmxCpu->VmMsrBitMapPhy.QuadPart);

	

	//扩展
	mark = SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_INVPCID;
	
	
	if (VmxEptInit())
	{
		//mark |= SECONDARY_EXEC_ENABLE_VPID | SECONDARY_EXEC_ENABLE_EPT;
		//__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, vmxCpu->cpuNumber + 1);
		mark |= SECONDARY_EXEC_ENABLE_EPT;
		__vmx_vmwrite(EPT_POINTER, vmxCpu->eptp->Flags);
	}
	msrValue = VmxAdjustMsrValue(mark, IA32_MSR_VMX_PROCBASED_CTLS2);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, msrValue);


	//设置拦截 int 3
	//mark = 1 << 3;
	//mark = 1 << 14;
	//
	////所有都拦截
	//__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 3);
	//__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 3);
	//
	//__vmx_vmwrite(EXCEPTION_BITMAP, mark);


}

BOOLEAN VMXInitVmcs(ULONG64 HostRIP, ULONG64 guestRip, ULONG64 GuestRsp)
{

	PVMXCPU vmxCpu = VmxGetCurrentEntry();

	PHYSICAL_ADDRESS low, hei;
	low.QuadPart = 0;
	hei.QuadPart = MAXULONG64;
	vmxCpu->VmHostStackTop = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 36, low, hei, low, MmCached);

	memset(vmxCpu->VmHostStackTop, 0, PAGE_SIZE * 36);
	
	vmxCpu->VmHostStackBase = (PVOID)((ULONG64)vmxCpu->VmHostStackTop + PAGE_SIZE * 35);

	vmxCpu->VmCsMemory = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);

	memset(vmxCpu->VmCsMemory,0,PAGE_SIZE);

	vmxCpu->VmCsPhy = MmGetPhysicalAddress(vmxCpu->VmCsMemory);


	vmxCpu->VmMsrBitMap = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);

	memset(vmxCpu->VmMsrBitMap, 0, PAGE_SIZE);

	vmxCpu->VmMsrBitMapPhy = MmGetPhysicalAddress(vmxCpu->VmMsrBitMap);



	//写入身份ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	*(PULONG)vmxCpu->VmCsMemory = (ULONG)basic;


	int error = __vmx_vmclear(&vmxCpu->VmCsPhy.QuadPart);
	if (error)
	{
		DbgPrintEx(77, 0, "[db]:%s __vmx_vmclear err = %d\r\n", __FUNCTION__, error);
		return FALSE;
	}

	error = __vmx_vmptrld(&vmxCpu->VmCsPhy.QuadPart);

	if (error)
	{
		DbgPrintEx(77, 0, "[db]:%s __vmx_vmptrld err = %d\r\n", __FUNCTION__, error);
		return FALSE;
	}

	VMXInitGuestState(guestRip, GuestRsp);
	VMXInitHostState(HostRIP);
	VMXInitEntry();
	VMXInitExit();
	VMXInitControl();
	return TRUE;
}

BOOLEAN VMXInit(ULONG64 HostRIP)
{
	PULONG64 resultAddr = _AddressOfReturnAddress();

	BOOLEAN isSuccess = VMXInitVmOn();

	if (isSuccess)
	{
		isSuccess = VMXInitVmcs(HostRIP, *resultAddr, resultAddr + 1);

		if (!isSuccess)
		{
			VmxFreeMemory();
		}
		else
		{
			int error = __vmx_vmlaunch();
			DbgPrintEx(77, 0, "[db]:__vmx_vmlaunch = %d,error = %llx\r\n", error,VmxReadField(VM_INSTRUCTION_ERROR));
			if (error)
			{
				VmxFreeMemory();
			}
		}
	}

	return isSuccess;
}
