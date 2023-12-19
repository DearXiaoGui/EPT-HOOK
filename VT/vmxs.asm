.code

extern VmxExitHandler:proc
extern MyOpenProcess:proc
extern JmpOpenProcessRet:dq

AsmGetGdtTable proc
 sgdt [rcx];
 ret;
AsmGetGdtTable endp;


AsmReadES proc
	xor eax,eax;
	mov ax,es;
	ret;
AsmReadES endp
	
AsmReadCS proc
	xor eax,eax;
	mov ax,cs;
	ret;
AsmReadCS endp

AsmReadSS proc
	xor eax,eax;
	mov ax,ss;
	ret;
AsmReadSS endp

AsmReadDS proc
	xor eax,eax;
	mov ax,ds;
	ret;
AsmReadDS endp

AsmReadFS proc
	xor eax,eax;
	mov ax,fs;
	ret;
AsmReadFS endp

AsmReadGS proc
	xor eax,eax;
	mov ax,gs;
	ret;
AsmReadGS endp

AsmReadTR proc
	xor eax,eax;
	str ax;
	ret;

AsmReadTR endp

AsmReadLDTR proc
	xor eax,eax;
	sldt ax
	ret;
AsmReadLDTR endp


AsmVmxExitHandler proc
	push r15;
	push r14;
	push r13;
	push r12;
	push r11;
	push r10;
	push r9;
	push r8;
	push rdi;
	push rsi;
	push rbp;
	push rsp;
	push rbx;
	push rdx;
	push rcx;
	push rax;
	
	mov rcx,rsp;
	sub rsp,0100h
	call VmxExitHandler
	add rsp,0100h;

	pop rax;
	pop rcx;
	pop rdx;
	pop rbx;
	pop rsp;
	pop rbp;
	pop rsi;
	pop rdi;
	pop r8;
	pop r9;
	pop r10;
	pop r11;
	pop r12;
	pop r13;
	pop r14;
	pop r15;
	vmresume
	ret
AsmVmxExitHandler endp
;
;
AsmInvd proc
	invd;
	ret
AsmInvd endp;
;
AsmVmCall proc
	mov rax,rcx; //��־
	vmcall
	ret;
AsmVmCall endp;

AsmVmCallHook proc
	mov rax,rcx; //��־
	mov rcx,rdx;
	mov rdx,r8;
	mov r8,r9;
	mov r9,qword ptr [rsp+028h];
	vmcall
	ret;
AsmVmCallHook endp;
;
AsmJmpRet proc
	mov rsp,rdx;
	jmp rcx;
	ret;
AsmJmpRet endp;
;
AsmWriteCr2 proc
	mov cr2,rcx;
	ret;
AsmWriteCr2 endp;

AsmLgdt proc
	lgdt fword ptr [rcx]
	ret;
AsmLgdt endp;


;
;AsmInvvpid PROC
;
;    invvpid rcx, oword ptr [rdx]
;    jz      ErrorWithStatus
;    jc      ErrorCodeFailed
;    xor     rax, rax
;    ret
;    
;ErrorWithStatus:
;    mov     rax, 1
;    ret
;
;ErrorCodeFailed:
;    mov     rax, 2
;    ret
;    
;AsmInvvpid ENDP
;
;
Asminvept proc
	invept rcx, OWORD PTR [rdx]
	ret;
Asminvept endp


AsmNtOpenProcess proc
	push r15;
	push r14;
	push r13;
	push r12;
	push r11;
	push r10;
	push r9;
	push r8;
	push rdi;
	push rsi;
	push rbp;
	push rsp;
	push rbx;
	push rdx;
	push rcx;
	push rax;
	
	mov rcx,rsp;
	sub rsp,0100h
	call MyOpenProcess
	add rsp,0100h;

	pop rax;
	pop rcx;
	pop rdx;
	pop rbx;
	pop rsp;
	pop rbp;
	pop rsi;
	pop rdi;
	pop r8;
	pop r9;
	pop r10;
	pop r11;
	pop r12;
	pop r13;
	pop r14;
	pop r15;

	sub   rsp,38h
	mov   rax,qword ptr gs:[188h]
	;//WIN7
	;mov   r10b,byte ptr [rax+1F6h]
	mov   r10b,byte ptr [rax+232h]
	jmp qword ptr [JmpOpenProcessRet];
	
AsmNtOpenProcess endp
;

end


