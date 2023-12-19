#include "VmxEpt.h"
#include <intrin.h>
#include "VTDefine.h"
#include "VTTools.h"
#include "vmxs.h"
#include "VmxEptHook.h"

#define EPML4_INDEX(__ADDRESS__)		((__ADDRESS__ >> 39) & 0x1FF)
#define EPDPTE_INDEX(__ADDRESS__)		((__ADDRESS__ >> 30) & 0x1FF)
#define EPDE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 21) & 0x1FF)
#define EPTE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 12) & 0x1FF)

#define ACCESS_EPT_READ		1
#define ACCESS_EPT_WRITE	2
#define ACCESS_EPT_EXECUTE	4

BOOLEAN VmxIsEptSupport()
{
	ULONG64 vpidCap = __readmsr(IA32_MSR_VMX_EPT_VPID_CAP);

	BOOLEAN isOneExecute = vpidCap & 1;
	BOOLEAN isLevel4 = (vpidCap >> 6) & 1;

	return isOneExecute && isLevel4;
}


BOOLEAN VmxEptInit()
{
	if (!VmxIsEptSupport()) return FALSE;

	PVMXCPU entry = VmxGetCurrentEntry();


	entry->eptp = (PVMX_EPTP)ExAllocatePool(NonPagedPool, sizeof(VMX_EPTP));
	
	PHYSICAL_ADDRESS low, hei;
	low.QuadPart = 0;
	hei.QuadPart = MAXULONG64;
	entry->eptVmx = MmAllocateContiguousMemorySpecifyCache(sizeof(VMX_MAMAGER_PAGE_ENTRY), low, hei, low, MmCached);
	
	if (!entry->eptVmx)
	{
		ExFreePool(entry->eptp);
		entry->eptp = NULL;
		DbgPrintEx(77, 0, "[db]:allocate ept memory failed\r\n");
		return FALSE;
	}

	memset(entry->eptVmx, 0, sizeof(VMX_MAMAGER_PAGE_ENTRY));


	ULONG64 vpidCap = __readmsr(IA32_MSR_VMX_EPT_VPID_CAP);
	
	ULONG memoryType = ((vpidCap >> 14) & 1) == 1 ? 6 : 0;
	ULONG Dri = ((vpidCap >> 21) & 1);

	entry->eptVmx->pmlt[0].Flags = 0;
	entry->eptVmx->pmlt[0].ExecuteAccess = 1;
	entry->eptVmx->pmlt[0].ReadAccess = 1;
	entry->eptVmx->pmlt[0].WriteAccess = 1;
	entry->eptVmx->pmlt[0].PageFrameNumber = MmGetPhysicalAddress(&entry->eptVmx->pdptt[0]).QuadPart / PAGE_SIZE;

	for (int i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		entry->eptVmx->pdptt[i].Flags = 0;
		entry->eptVmx->pdptt[i].ExecuteAccess = 1;
		entry->eptVmx->pdptt[i].ReadAccess = 1;
		entry->eptVmx->pdptt[i].WriteAccess = 1;
		entry->eptVmx->pdptt[i].PageFrameNumber = MmGetPhysicalAddress(entry->eptVmx->pdt[i]).QuadPart / PAGE_SIZE;

		for (int j = 0; j < PDE_ENTRY_COUNT; j++)
		{
			entry->eptVmx->pdt[i][j].Flags = 0;
			entry->eptVmx->pdt[i][j].ExecuteAccess = 1;
			entry->eptVmx->pdt[i][j].ReadAccess = 1;
			entry->eptVmx->pdt[i][j].WriteAccess = 1;
			entry->eptVmx->pdt[i][j].PageFrameNumber = i * 512 + j;
			entry->eptVmx->pdt[i][j].MemoryType = memoryType;
			entry->eptVmx->pdt[i][j].LargePage = 1;
		}
	}

	entry->eptp->Flags = 0;
	entry->eptp->EnableAccessAndDirtyFlags = Dri;
	entry->eptp->MemoryType = memoryType;
	entry->eptp->PageWalkLength = 3;
	entry->eptp->PageFrameNumber = MmGetPhysicalAddress(&entry->eptVmx->pmlt[0]).QuadPart / PAGE_SIZE;

	return TRUE;
}

PEPDE_2MB VmxGpaToHpaPde(ULONG64 gpa)
{
	ULONG64 pml4Index = EPML4_INDEX(gpa);

	if (pml4Index > 0) return NULL;

	PVMXCPU entry = VmxGetCurrentEntry();

	ULONG64 pdpteIndex = EPDPTE_INDEX(gpa);
	ULONG64 pdeIndex = EPDE_INDEX(gpa);

	return &entry->eptVmx->pdt[pdpteIndex][pdeIndex];
}

PEPTE VmxGetEPTE(ULONG64 gpa)
{
	PEPDE_2MB pde2m = VmxGpaToHpaPde(gpa);

	if (pde2m->LargePage) return NULL;

	ULONG index = EPTE_INDEX(gpa);

	PEPDE pde = (PEPDE)pde2m;

	ULONG64 PageFrame = pde->PageFrameNumber * PAGE_SIZE;

	PHYSICAL_ADDRESS phyPage = {0};
	phyPage.QuadPart = PageFrame;

	PEPTE pte = (PEPTE)MmGetVirtualForPhysical(phyPage);

	return &pte[index];
}


VOID EptLargePageSplitPage(ULONG64 gpa)
{
	PEPDE_2MB pde2m = VmxGpaToHpaPde(gpa);
	if (!pde2m->LargePage) return 0;
	
	PVMXCPU vmxEntry = VmxGetCurrentEntry();

	PEPTE hookPte = (PEPTE)ExAllocatePool(NonPagedPool, PAGE_SIZE);


	for (int i = 0; i < PTE_ENTRY_COUNT; i++)
	{
		hookPte[i].Flags = 0;
		hookPte[i].ExecuteAccess = 1;
		hookPte[i].WriteAccess = 1;
		hookPte[i].ReadAccess = 1;
		hookPte[i].MemoryType = pde2m->MemoryType;
		hookPte[i].PageFrameNumber = (pde2m->PageFrameNumber << 9) + i;
	}
	pde2m->Flags = 0;
	PEPDE pde = (PEPDE)pde2m;

	pde->PageFrameNumber = MmGetPhysicalAddress(hookPte).QuadPart / PAGE_SIZE;
	pde->ExecuteAccess = 1;
	pde->WriteAccess = 1;
	pde->ReadAccess = 1;
	//Ë¢ÐÂÒ³±í
	Asminvept(2, &vmxEntry->eptp->Flags);
}



VOID VmxEptEntryHook(ULONG64 kernelCr3, ULONG64 HookGpa, ULONG64 newGpa, PULONG64 retValue)
{
	//DbgBreakPoint();
	ULONG64 oldCr3 = __readcr3();

	__writecr3(kernelCr3 | 2);

	ULONG64 HookGpaPage = HookGpa * PAGE_SIZE;
	ULONG64 NEWGpaPage = newGpa * PAGE_SIZE;

	PEPDE_2MB pde2mhook = VmxGpaToHpaPde(HookGpaPage);

	PEPDE_2MB pde2mnew = VmxGpaToHpaPde(NEWGpaPage);

	PVMXCPU vmxEntry = VmxGetCurrentEntry();

	do 
	{
		if (!pde2mhook || !pde2mnew)
		{
			break;
		}

		if (pde2mhook->LargePage)
		{
			//ÇÐ¸î
			EptLargePageSplitPage(HookGpaPage);
		}


		if (pde2mnew->LargePage)
		{
			//ÇÐ¸î
			EptLargePageSplitPage(NEWGpaPage);
		}

		PEPTE hookpte = VmxGetEPTE(HookGpaPage);

		PEPTE newpte = VmxGetEPTE(NEWGpaPage);

		if (!hookpte || !newpte)
		{
			break;
		}
		
		if (retValue)
		{
			*retValue = hookpte->PageFrameNumber;
		}

		hookpte->PageFrameNumber = newpte->PageFrameNumber;

		hookpte->ExecuteAccess = 0;
	} while (0);

	


	__writecr3(oldCr3);
}


VOID VmxEptUpdate(ULONG64 access,ULONG64 cr3,ULONG64 lineAddress,ULONG64 gpa)
{
	PEPTE hookpte = VmxGetEPTE(gpa);

	
	if (!hookpte) return;

	ULONG64 oldCr3 = __readcr3();
	__writecr3(cr3);

	PEptHookContext context = VmxEptGetHookContext(lineAddress);

	__writecr3(oldCr3);

	if (!context) return;

	if (access == ACCESS_EPT_READ || access == ACCESS_EPT_WRITE)
	{
		hookpte->PageFrameNumber = context->HookHpaPageNumber;
		hookpte->ReadAccess = 1;
		hookpte->WriteAccess = 1;
		hookpte->ExecuteAccess = 0;
	
		return;
	}


	if (access == ACCESS_EPT_EXECUTE)
	{
		PEPTE newpte = VmxGetEPTE(context->NewPageNumber * PAGE_SIZE);
		if (!newpte) return;

		hookpte->PageFrameNumber = newpte->PageFrameNumber;
		hookpte->ReadAccess = 0;
		hookpte->WriteAccess = 0;
		hookpte->ExecuteAccess = 1;
	}
}


VOID VmxEptHandler(PGUEST_CONTEXT context)
{
	union
	{
		struct
		{
			ULONG64 read : 1;
			ULONG64 write : 1;
			ULONG64 execute : 1;

			ULONG64 readable : 1;
			ULONG64 writeable : 1;
			ULONG64 executeable : 1;
			ULONG64 un1 : 1;
			ULONG64 vaild : 1;
			ULONG64 translation : 1;
			ULONG64 un2 : 3;
			ULONG64 NMIUnblocking : 1;
			ULONG64 un3 : 51;
		};
		ULONG64 flags;
	}eptinfo;


	eptinfo.flags = VmxReadField(EXIT_QUALIFICATION);
	ULONG64 linearAddress = VmxReadField(GUEST_LINEAR_ADDRESS);
	ULONG64 gpa = VmxReadField(GUEST_PHYSICAL_ADDRESS);
	ULONG64 cr3 = VmxReadField(GUEST_CR3);

	PVMXCPU vmxEntry = VmxGetCurrentEntry();

	if (eptinfo.read)
	{
		VmxEptUpdate(ACCESS_EPT_READ, cr3, linearAddress, gpa);
		Asminvept(2, &vmxEntry->eptp->Flags);
	}

	if (eptinfo.write)
	{
		VmxEptUpdate(ACCESS_EPT_WRITE, cr3, linearAddress, gpa);
		Asminvept(2, &vmxEntry->eptp->Flags);
	}


	if (eptinfo.execute)
	{
		VmxEptUpdate(ACCESS_EPT_EXECUTE, cr3, linearAddress, gpa);
		Asminvept(2, &vmxEntry->eptp->Flags);
	}


}