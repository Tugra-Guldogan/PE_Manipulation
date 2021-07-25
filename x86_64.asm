EXTRN VirtualProtect : PROJ

.DATA
dummy	DD ?

.CODE

spoof_data PROC

	; INFO: Unoptimized assembly code to improve readability

	push    rsi
	push    rdi
	sub     rsp, 40h

	mov     rax, gs:[60h]		; PEB
	mov     rax, [rax + 18h]	; Ldr
	mov     rax, [rax + 20h]	; InMemoryOrderModuleList
	mov     rax, [rax]			; Skip our module and get to ntdll
	mov     rax, [rax]			; Skip ntdll and get to kernel32
	mov     rcx, [rax + 20h]	; rcx = DllBase for kernel32

	mov     eax, [rcx + 3Ch]	; e_lfanew
	add     rax, rcx			; rax = IMAGE_NT_HEADERS64
	lea     rax, [rax + 18h]	; rax = IMAGE_OPTIONAL_HEADER64
	lea     rax, [rax + 70h]	; rax = IMAGE_DATA_DIRECTORY
	lea     rax, [rax + 0h]		; rax = IMAGE_DATA_DIRECTORY for IMAGE_DIRECTORY_ENTRY_EXPORT

	mov     edx, [rax]			; rdx = VirtualAddress
	lea     rax, [rcx + rdx]	; rax = IMAGE_EXPORT_DIRECTORY

	mov     edx, [rax + 18h]	; rdx = NumberOfNames
	mov     r8d, [rax + 20h]	; r8 = AddressOfNames
	lea     r8, [rcx + r8]

	xor     rsi, rsi
	xor     rdi, rdi

	mov     r10, 6f736e6f43746553h	 ;	SetConso
	mov     r11, 0065646f4d656c6fh	 ;	oleMode\0

@@1:
	mov     r9d, [r8]
	lea     r9, [rcx + r9]		; function name

	; search for SetConsoleMode
	cmp     r10, [r9]
	jnz     @@2
	cmp     r11, [r9 + 7]
	jnz     @@2

	; prevent repeated matches (just in case)
	test    rsi, rsi
	jnz     @@bad

	; got it! remember the index
	mov     rsi, rdx
	neg     rsi

@@2:
	add     r8, 4
	dec     rdx
	jnz     @@1
	
	; Did we find our first function?
	test    rsi, rsi
	jz      @@bad

	mov     edx, [rax + 18h]	; rdx = NumberOfNames
	mov     r8d, [rax + 20h]	; r8 = AddressOfNames
	lea     r8, [rcx + r8]

@@3:
	mov     r9d, [r8]
	lea     r9, [rcx + r9]		; function name

	; Search for WinExec
	cmp     word ptr [r9], 6957h
	jnz     @@4
	cmp     byte ptr [r9 + 3], 45h
	jnz     @@4
	cmp     byte ptr [r9 + 7], 0
	jnz     @@4

	; prevent repeated matches (just in case)
	test    rdi, rdi
	jnz     @@bad

	; got it, remember the index
	mov     rdi, rdx
	neg     rdi

@@4:
	add     r8, 4
	dec     rdx
	jnz     @@3

	; Did we find our second function?
	test    rdi, rdi
	jz      @@bad


	; Convert two of the indices that we found
	; to addresses in AddressOfNameOrdinals array in mapped PE file

	mov     r10d, [rax + 18h]	; r10 = NumberOfNames
	lea     rsi, [r10 + rsi]	; rsi = function index in NumberOfNames: SetConsoleMode
	lea     rdi, [r10 + rdi]	; rdi = function index in NumberOfNames: WinExec

	mov     r10d, [rax + 24h]	; r10 = AddressOfNameOrdinals
	lea     r10, [rcx + r10]

	lea     rsi, [r10 + rsi * 2]	; rsi = address of index of SetConsoleMode in the AddressOfNameOrdinals table
	lea     rdi, [r10 + rdi * 2]	; rdi = address of index of WinExec in the AddressOfNameOrdinals table

		
	; Change memory protection
	mov     rcx, rsi
	mov     rdx, 2
	mov     r8, 4				; 4 = PAGE_READWRITE
	lea     r9, dummy
	call    VirtualProtect
	test    rax, rax
	jz      @@bad

	; Just in case two addresses span to another page
	mov     rcx, rdi
	mov     rdx, 2
	mov     r8, 4				; 4 = PAGE_READWRITE
	lea     r9, dummy
	call    VirtualProtect
	test    rax, rax
	jz      @@bad


	; Swap WORD indices for two APIs
	mov     ax, word ptr [rsi]
	mov     cx, word ptr [rdi]
	mov     word ptr [rsi], cx
	mov     word ptr [rdi], ax


	; We can technically restore back the memory protection here ....


	; Success
	xor     eax, eax
	inc     rax

	add     rsp, 40h
	pop     rdi
	pop     rsi
	ret

bad:
	; Failure
	xor     eax, eax

	add     rsp, 40h
	pop     rdi
	pop     rsi
	ret
spoof_data ENDP
