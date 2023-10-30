#pragma once
#include <Windows.h>
#include "file.h"

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PVOID DllBase)
{
    if (!DllBase) return NULL;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)DllBase + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_DATA_DIRECTORY* ExportDirectoryEntry = 
        &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDirectoryEntry->VirtualAddress == 0 || ExportDirectoryEntry->Size == 0)
        return NULL;

    return (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)DllBase + ExportDirectoryEntry->VirtualAddress);
}

PVOID GetTextSegmentInfoMapped(PVOID DllBase, PDWORD TextSegmentSize)
{
    if (!DllBase) return NULL;

    IMAGE_DOS_HEADER* DosHeader = (PIMAGE_DOS_HEADER)DllBase;
    
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((char*)DllBase + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL; 
    }

    IMAGE_SECTION_HEADER* SectionHeader = (IMAGE_SECTION_HEADER*)((char*)NtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
    {
        if (memcmp(SectionHeader->Name, ".text", 5) == 0)
        {
            *TextSegmentSize = SectionHeader->SizeOfRawData;
            return (PVOID)((char*)DllBase + SectionHeader->VirtualAddress);
        }
    }

    return NULL; // .text section not found
}


PVOID GetTextSegmentUnmapped(CONST PBYTE Buffer, DWORD* TextSegmentSize)
{
    if (!Buffer) return NULL;

    IMAGE_DOS_HEADER* DosHeader = (PIMAGE_DOS_HEADER)Buffer;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(Buffer + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL; 
    }

    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)NtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
    {
        if (memcmp(SectionHeader->Name, ".text", 5) == 0)
        {
            *TextSegmentSize = SectionHeader->SizeOfRawData;
            return (PVOID)(Buffer + SectionHeader->PointerToRawData);
        }
    }

    return NULL; // .text section not found
}