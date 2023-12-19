#include "VmxHandler.h"
#include <intrin.h>
#include "VTDefine.h"
#include "vmxs.h"
#include "VTTools.h"
#include "VmxEpt.h"
#include "vmx.h"

#define REG_MAKE(HH,CC) ((CC<<32) | (HH & 0xffffffff))

VOID InjectExceptionEvent(ULONG64 type, ULONG64 vector)
{

	//注入指令前事件
	__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	VMXExitIntEvent VmEvent = { 0 };
	VmEvent.vaild = 1;
	VmEvent.type = type;
	VmEvent.vector = vector;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, *(PULONG64)&VmEvent);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);

}


VOID VmxHandlerCpuid(PGUEST_CONTEXT context)
{
	ULONG64 functionNumber = context->mRax;
	ULONG64 leaf = context->mRcx;

	if (functionNumber == 0x12345678)
	{
		context->mRax = 0x11111111;
		context->mRbx = 0x22222222;
		context->mRcx = 0x33333333;
		context->mRdx = 0x44444444;

		//VmxSetMTF(TRUE);
		//VMXExitIntEvent eventInfo = {0};
		//eventInfo.vaild = 1;
		//eventInfo.vector = 0;
		//eventInfo.type = 7;
		//
		//__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, *(PULONG64)&eventInfo);
		//__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);
	}
	else 
	{
		int cpuinfo[4] = {0};
		__cpuidex(cpuinfo, functionNumber, leaf);

		context->mRax = cpuinfo[0];
		context->mRbx = cpuinfo[1];
		context->mRcx = cpuinfo[2];
		context->mRdx = cpuinfo[3];
	}
}

VOID VmxHandlerInvpcid(PGUEST_CONTEXT context)
{
	ULONG64 guestRsp = VmxReadField(GUEST_RSP);
	ULONG64 qualification = VmxReadField(EXIT_QUALIFICATION);
	ULONG64 info = VmxReadField(VMX_INSTRUCTION_INFO);
	PINVPCID pcidinfo = (PINVPCID)&info;

	PULONG64 regs = (PLONG64)context;

	ULONG64 optIndex = pcidinfo->regOpt;

	//invcpid rsp, dword ptr ds : [rax + rsi*scale + 0xc];

	ULONG64 base = 0;
	ULONG64 index = 0;
	
	if (!pcidinfo->baseInvaild)
	{
		if (pcidinfo->base == 4)
		{
			base = guestRsp;
		}
		else 
		{
			base = regs[pcidinfo->base];
		}

		
	}
	
	if (!pcidinfo->indexInvaild)
	{
		if (pcidinfo->index == 4)
		{
			index = guestRsp;
		}
		else
		{
			index = regs[pcidinfo->index];
		}

	}

	if (pcidinfo->scale)
	{
		index = index  * (1 << pcidinfo->scale);
	}

	base = base + index + qualification;

	//ULONG64 value = 0;
	//
	//if (pcidinfo->addrssSize == 0)
	//{
	//	value = *(PUSHORT)base;
	//}
	//else if (pcidinfo->addrssSize == 1)
	//{
	//	value = *(PULONG)base;
	//}
	//else if (pcidinfo->addrssSize == 2)
	//{
	//	value = *(PULONG64)base;
	//}

	if (optIndex == 4)
	{
		_invpcid(guestRsp, (PVOID)base);
	}
	else 
	{
		_invpcid(regs[optIndex], (PVOID)base);
	}

	
}

VOID VmxHandlerException(PGUEST_CONTEXT context)
{
	ULONG64 guestRip = VmxReadField(GUEST_RIP);
	ULONG64 guestRsp = VmxReadField(GUEST_RSP);
	ULONG64 codelen = VmxReadField(VM_EXIT_INSTRUCTION_LEN);
	
	ULONG64 info = VmxReadField(VM_EXIT_INTR_INFO);
	ULONG64 error = VmxReadField(VM_EXIT_INTR_ERROR_CODE);

	PVMXExitIntEvent eventInfo = (PVMXExitIntEvent)&info;

	if (!eventInfo->vaild)
	{
		__vmx_vmwrite(GUEST_RIP, guestRip + codelen);
		__vmx_vmwrite(GUEST_RSP, guestRsp);
		return;
	}

	if (eventInfo->errorCode)
	{
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error);
	}


	switch (eventInfo->type)
	{
		case EXCEPTION_W_INT	:
			break;
		case EXCEPTION_NMI_INT	:
			break;
		case EXCEPTION_HARDWARE	:
		{
			if (eventInfo->vector == 0xe)
			{
				ULONG64 liner = VmxReadField(GUEST_LINEAR_ADDRESS);
				ULONG64 expcetionAddress = VmxReadField(EXIT_QUALIFICATION);
				AsmWriteCr2(expcetionAddress);
				//DbgBreakPoint();
			
				__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, info);
				__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, codelen);

				codelen = 0;
			}
		}
			break;
		case EXCEPTION_SOFT		:	
		{
			if (eventInfo->vector == 3)
			{
				DbgPrintEx(77, 0, "[db]:int 3 \r\n");
				//eventInfo->vector = 0x1d;
				__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, info);
				__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, codelen);
				codelen = 0;
			}
		
		}
			break;
	}


	__vmx_vmwrite(GUEST_RIP, guestRip + codelen);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
	return;
}

void VmxHandlerMTF(PGUEST_CONTEXT context)
{
	ULONG64 guestRip = VmxReadField(GUEST_RIP);
	ULONG64 guestRsp = VmxReadField(GUEST_RSP);
	ULONG64 codelen = VmxReadField(VM_EXIT_INSTRUCTION_LEN);
	VmxSetMTF(FALSE);
	
}




EXTERN_C void VmxExitHandler(PGUEST_CONTEXT context)
{
	ULONG64 reason = VmxReadField(VM_EXIT_REASON);
	ULONG64 guestRip = VmxReadField(GUEST_RIP);
	ULONG64 guestRsp = VmxReadField(GUEST_RSP);
	ULONG64 codelen = VmxReadField(VM_EXIT_INSTRUCTION_LEN);

	ULONG mreason = reason & 0xFFFF;

	//DbgPrintEx(77, 0, "[db]:mreason = %d\r\n", mreason);

	switch (mreason)
	{
		case EXIT_REASON_EXCEPTION_NMI:
			VmxHandlerException(context);
			return;

		case EXIT_REASON_CPUID:
		{
			VmxHandlerCpuid(context);
		}
		break;

		case EXIT_REASON_VMCALL		:
		{
			if (context->mRax == 'exit')
			{

				GdtTable gdtTable = {0};
				GdtTable idtTable = {0};
				gdtTable.Base =  VmxReadField(GUEST_GDTR_BASE);
				gdtTable.limit = VmxReadField(GUEST_GDTR_LIMIT);
				idtTable.Base = VmxReadField(GUEST_IDTR_BASE);
				idtTable.limit = VmxReadField(GUEST_IDTR_LIMIT);
				ULONG64 eflgs = VmxReadField(GUEST_RFLAGS);
				__vmx_off();

				__lidt(&idtTable);
				AsmLgdt(&gdtTable);
				__writeeflags(eflgs);
				//还原RIP，RSP
				
				PVMXCPU vmxCpu = VmxGetCurrentEntry();

				//if (vmxCpu->cpuNumber == 0)
				//{
				//	DbgBreakPoint();
				//}
				vmxCpu->isSuccessVmOn = FALSE;

				AsmJmpRet(guestRip + codelen, guestRsp);
				return;
			}
			else if (context->mRax == _EPT_HOOK_TAG)
			{
				VmxEptEntryHook(context->mRcx, context->mRdx, context->mR8, context->mR9);
			}
			else if (context->mRax == _EPT_UNHOOK_TAG)
			{

			}
			else 
			{
				ULONG64 flags = VmxReadField(GUEST_RFLAGS);
				flags |= 0x41;
				__vmx_vmwrite(GUEST_RFLAGS, flags);
			}
			
		}
		break;
		case EXIT_REASON_VMCLEAR	:
		case EXIT_REASON_VMLAUNCH	:
		case EXIT_REASON_VMPTRLD	:
		case EXIT_REASON_VMPTRST	:
		case EXIT_REASON_VMREAD		:
		case EXIT_REASON_VMRESUME	:
		case EXIT_REASON_VMWRITE	:
		case EXIT_REASON_VMXOFF		:
		case EXIT_REASON_VMXON		:
		{
			ULONG64 flags = VmxReadField(GUEST_RFLAGS);
			flags |= 0x41;
			__vmx_vmwrite(GUEST_RFLAGS, flags);
		}
		break;

		case EXIT_REASON_INVD:
		{
			AsmInvd();
		}
			break;

		case EXIT_REASON_XSETBV:
		{
			DbgPrintEx(77, 0, "[db]:XSETBV\r\n");
			ULONG64 value = REG_MAKE(context->mRax, context->mRdx);
			_xsetbv(context->mRcx, value);
		}
		break;

		case EXIT_REASON_MTF:
		{
			VmxHandlerMTF(context);
			codelen = 0;
		}
		break;

		case EXIT_REASON_RDTSCP:
		{
			DbgPrintEx(77, 0, "[db]:RDTSCP\r\n");
			int x = 0;
			LARGE_INTEGER inTime = { 0 };
			inTime.QuadPart =  __rdtscp(&x);

			context->mRax = inTime.LowPart;
			context->mRdx = inTime.HighPart;
			context->mRcx = x;

		}
		break;

		case EXIT_REASON_INVPCID:
		{

			DbgPrintEx(77, 0, "[db]:INVPCID\r\n");

			VmxHandlerInvpcid(context);

			

		}
		break;

		case EXIT_REASON_MSR_READ:
		{
			DbgPrintEx(77, 0, "[DB]:msr index = %x\r\n", context->mRcx);
			ULONG64 value = __readmsr(context->mRcx);
			context->mRax = value & 0xffffffff;
			context->mRdx = (value >> 32) & 0xffffffff;
		}
		break;

		case EXIT_REASON_EPT_VIOLATION:
		{
			VmxEptHandler(context);
			codelen = 0;
		}
		break;
		
		case EXIT_REASON_EPT_CONFIG:
			DbgPrintEx(77, 0, "[DB]:EXIT_REASON_EPT_CONFIG = %d\r\n", EXIT_REASON_EPT_CONFIG);
			break;
	}

	ULONG64 rf = 0;
	__vmx_vmread(GUEST_RFLAGS, &rf);
	if ((rf & 0x100) == 0x100)
	{
		//注入一个硬件调试中断
		InjectExceptionEvent(3, 1);

		/*
		  mov ax,ss
		  mov ss,ax
		  iretd
		  mov rax,0x12345678
		  mov eax,eax
		*/

		ULONG64 info = 0;  
		__vmx_vmread(GUEST_INTERRUPTIBILITY_INFO, &info);
		info &= ~2;
		__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, info);

	}


	__vmx_vmwrite(GUEST_RIP, guestRip + codelen);
	__vmx_vmwrite(GUEST_RSP, guestRsp);


}