#pragma once
#include <Windows.h>

PVOID ReadFileWrapper(CONST PWCHAR FilePath, PDWORD BufferSize)
{
    PBYTE Buffer = NULL;
    HANDLE FileHandle = CreateFileW(
        FilePath, 
        GENERIC_READ, 
        0, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    DWORD FileSize = GetFileSize(FileHandle, NULL);
    if (FileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(FileHandle);
        return NULL;
    }

    Buffer = (PBYTE)HeapAlloc(
        GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        FileSize
    );

    if (Buffer == NULL)
    {
        CloseHandle(FileHandle);
        return NULL;
    }

    if (ReadFile(
        FileHandle, 
        Buffer, 
        FileSize, 
        BufferSize, 
        NULL) 
            == FALSE)
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
        *BufferSize = 0;
    }

    CloseHandle(FileHandle);
    *BufferSize = FileSize;
    return Buffer;
}