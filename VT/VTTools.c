#include "VTTools.h"
#include "VTDefine.h"
#include <intrin.h>

BOOLEAN VmxIsBIOSStartVT()
{
	ULONG64 control = __readmsr(IA32_FEATURE_CONTROL);

	if ((control & 5) == 5)
	{
		return TRUE;
	}

	if ((control & 1) == 1) return FALSE;

	control |= 5;

	__writemsr(IA32_FEATURE_CONTROL, control);

	control = __readmsr(IA32_FEATURE_CONTROL);

	return (control & 5) == 5;
}

BOOLEAN VmxIsCpuIdSuportVT()
{
	ULONG cpuidinfo[4];

	__cpuidex(cpuidinfo, 1, 0);

	return (cpuidinfo[2] >> 5) & 1;
}

BOOLEAN VmxIsCr4EnableVT()
{
	ULONG64 mcr4 = __readcr4();

	return ((mcr4 >> 13) & 1) == 0;
}


//****************************************************************************

VMXCPU vmxCpuEntrys[128];

PVMXCPU VmxGetCurrentEntry()
{
	ULONG number = KeGetCurrentProcessorNumberEx(NULL);

	return &vmxCpuEntrys[number];
}


ULONG64 VmxAdjustMsrValue(ULONG64 Value, ULONG64 msr)
{
	LARGE_INTEGER msrValue;
	msrValue.QuadPart =__readmsr(msr);
	Value |= msrValue.LowPart;
	Value &= msrValue.HighPart;

	return Value;
}

BOOLEAN VmxIsControlTure()
{
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	return ((basic >> 55)  & 1);
}

ULONG64 VmxReadField(ULONG64 idField)
{
	ULONG64 value = 0;
	__vmx_vmread(idField, &value);

	return value;
}


BOOLEAN VmxSetReadMsrBitMap(PUCHAR bitMap, ULONG64 msr, BOOLEAN isEnable)
{
	

	if (msr >= 0xc0000000)
	{
		bitMap += 1024;
		msr -= 0xc0000000;
	}
	
	PUCHAR temp = 0;
	ULONG64 byteOffset = 0;
	ULONG64 mod = 0;
	if (msr != 0)
	{
		byteOffset = msr / 8;
		mod = msr % 8;
		temp = (bitMap + byteOffset);
		
	}
	else 
	{
		temp = bitMap;
	}

	if (isEnable)
	{
		*temp |= 1 << mod;
	}
	else 
	{
		*temp &= ~(1 << mod);
	}


	return TRUE;
	
}

BOOLEAN VmxSetWriteMsrBitMap(PUCHAR bitMap, ULONG64 msr, BOOLEAN isEnable)
{
	bitMap += 2048;

	if (msr >= 0xc0000000)
	{
		bitMap += 1024;
		msr -= 0xc0000000;
	}

	PUCHAR temp = 0;
	ULONG64 byteOffset = 0;
	ULONG64 mod = 0;
	if (msr != 0)
	{
		byteOffset = msr / 8;
		mod = msr % 8;
		temp = (bitMap + byteOffset);

	}
	else
	{
		temp = bitMap;
	}

	if (isEnable)
	{
		*temp |= 1 << mod;
	}
	else
	{
		*temp &= ~(1 << mod);
	}


	return TRUE;
}


VOID VmxSetMTF(BOOLEAN isOpen)
{
	ULONG64 Proccontorlmsr = VmxIsControlTure() ? IA32_MSR_VMX_TRUE_PROCBASED_CTLS : IA32_MSR_VMX_PROCBASED_CTLS;

	ULONG64 mark = VmxReadField(CPU_BASED_VM_EXEC_CONTROL);

	if (isOpen)
	{
		mark |= CPU_BASED_MONITOR_TRAP_FLAG;
	}
	else 
	{
		mark &= (~CPU_BASED_MONITOR_TRAP_FLAG);
	}

	ULONG64 msrValue = VmxAdjustMsrValue(mark, Proccontorlmsr);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, msrValue);

}