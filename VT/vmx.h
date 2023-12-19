#pragma once
#include <ntifs.h>

#pragma pack(push,1)
typedef struct _GdtTable
{
	USHORT limit;
	ULONG64 Base;
}GdtTable, *PGdtTable;
#pragma pack(pop)


BOOLEAN VMXInit(ULONG64 HostRIP);

VOID VMXExitOff();
