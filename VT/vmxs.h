#pragma once
#include <ntifs.h>

EXTERN_C VOID AsmGetGdtTable(PVOID tableBaseAddr);
EXTERN_C USHORT AsmReadES();
EXTERN_C USHORT AsmReadCS();
EXTERN_C USHORT AsmReadSS();
EXTERN_C USHORT AsmReadDS();
EXTERN_C USHORT AsmReadFS();
EXTERN_C USHORT AsmReadGS();
EXTERN_C USHORT AsmReadTR();
EXTERN_C USHORT AsmReadLDTR();

EXTERN_C void AsmVmxExitHandler();

EXTERN_C VOID AsmInvd();

EXTERN_C VOID AsmVmCall(ULONG exitCode);
EXTERN_C VOID AsmVmCallHook(ULONG hookTag, ULONG64 cr3, ULONG64 hookGPA, ULONG64 newGPA, PULONG64 retValue);
EXTERN_C VOID AsmJmpRet(ULONG64 rip,ULONG64 rsp);
EXTERN_C VOID AsmWriteCr2(ULONG64 address);
EXTERN_C void Asminvept(ULONG type, ULONG64 eptp);

EXTERN_C void AsmLgdt(PVOID gdtTable);

EXTERN_C NTSTATUS AsmNtOpenProcess();

//EXTERN_C NTSTATUS AsmNtCreateFile();

/*
EXTERN_C unsigned char  AsmInvvpid(unsigned long Type, void * Descriptors);


*/