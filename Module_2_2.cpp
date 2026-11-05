#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    // 1. Kiểm tra tham số dòng lệnh CLI
    if (argc < 2) {
        printf("[-] Usage: %s <path_to_shellcode.bin>\n", argv[0]);
        return -1;
    }

    const char* szFilePath = argv[1];
    printf("[i] Opening shellcode binary file: %s\n", szFilePath);

    // 2. Mở file nhị phân
    HANDLE hFile = CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open file. Error code: %d\n", GetLastError());
        return -1;
    }

    // 3. Lấy kích thước file
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0 || dwFileSize == INVALID_FILE_SIZE) {
        printf("[!] Invalid file size.\n");
        CloseHandle(hFile);
        return -1;
    }
    printf("[+] File size: %d bytes\n", dwFileSize);

    // 4. Cấp phát bộ nhớ Heap để đọc nội dung file
    PBYTE pBuffer = (PBYTE)malloc(dwFileSize);
    if (!pBuffer) {
        printf("[!] Memory allocation failed for file buffer.\n");
        CloseHandle(hFile);
        return -1;
    }

    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) {
        printf("[!] Failed to read file content.\n");
        free(pBuffer);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile);

    // 5. Cấp phát bộ nhớ ảo (Virtual Memory) với quyền READ-WRITE
    PVOID pExecMemory = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pExecMemory) {
        printf("[!] VirtualAlloc failed. Error code: %d\n", GetLastError());
        free(pBuffer);
        return -1;
    }
    printf("[+] Allocated executable memory at address: 0x%p\n", pExecMemory);

    // 6. Sao chép Shellcode vào bộ nhớ ảo vừa cấp phát
    memcpy(pExecMemory, pBuffer, dwFileSize);
    free(pBuffer); // Giải phóng bộ nhớ tạm trên Heap

    // 7. Thay đổi quyền bộ nhớ sang EXECUTE-READ (Chuẩn W^X)
    DWORD dwOldProtect = 0;
    if (!VirtualProtect(pExecMemory, dwFileSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        printf("[!] VirtualProtect failed. Error code: %d\n", GetLastError());
        VirtualFree(pExecMemory, 0, MEM_RELEASE);
        return -1;
    }

    // 8. Thực thi Shellcode bằng CreateThread
    printf("[i] Executing shellcode...\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecMemory, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateThread failed. Error code: %d\n", GetLastError());
        VirtualFree(pExecMemory, 0, MEM_RELEASE);
        return -1;
    }

    // Chờ luồng thực thi hoàn tất
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("[+] Shellcode execution completed successfully!\n");

    // 9. Dọn dẹp bộ nhớ ảo
    VirtualFree(pExecMemory, 0, MEM_RELEASE);
    return 0;
}
