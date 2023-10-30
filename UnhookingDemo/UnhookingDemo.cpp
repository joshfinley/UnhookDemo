#include <Windows.h>
#include "peb.h"
#include "pe.h"
#include "file.h"

#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)


#define JMP_REL16_32    0xE9
#define PUSH_IMM16_32   0x68
#define RETN            0xC3

#define HOOK_NONE       0
#define HOOK_RELATIVE	1
#define HOOK_ABSOLUTE	2


DWORD IsHooked(PBYTE FuncAddr, DWORD_PTR* AddrOffset)
{
    if (FuncAddr[0] == JMP_REL16_32)
    {
        *AddrOffset = 1;
        return HOOK_RELATIVE;
    }
    else if (FuncAddr[0] && FuncAddr[0] == RETN)
    {
        *AddrOffset = 1;
        return HOOK_ABSOLUTE;
    }

    return HOOK_NONE;
}

BOOL IsHookSameModule(PVOID FuncAddr, HMODULE ModuleBase)
{
    MEMORY_BASIC_INFORMATION MemBasicInfo = { NULL };
    VirtualQuery(
        FuncAddr,
        &MemBasicInfo,
        sizeof(MEMORY_BASIC_INFORMATION)
    );

    if (MemBasicInfo.AllocationBase = (PVOID)ModuleBase)
        return TRUE;

    return FALSE;
}

// Returns TRUE if hooks were found
DWORD UnhookModule(CONST PWCHAR ModuleName, CONST PWCHAR ModulePath)
{
    DWORD CleanBufferSize = NULL;
    PDWORD OrigFuncAddr = NULL;
    PDWORD OrigFuncName = NULL;
    PWORD OrigFuncOrdinal = NULL;

    PBYTE CleanModule = NULL;

    PIMAGE_EXPORT_DIRECTORY OrigExports = NULL;

    PLDR_MODULE OrigModule = FindPebModule(ModuleName);
    if (!OrigModule) return ERROR_NOT_FOUND;

    OrigExports = GetExportDirectory(OrigModule->BaseAddress);

    if (!OrigExports)
        return ERROR_FUNCTION_FAILED;


    OrigFuncAddr = RVA2VA(
        PDWORD,
        OrigModule,
        OrigExports->AddressOfFunctions
    );

    OrigFuncName = RVA2VA(
        PDWORD,
        OrigModule,
        OrigExports->AddressOfNames
    );

    OrigFuncOrdinal = RVA2VA(
        PWORD,
        OrigModule,
        OrigExports->AddressOfNameOrdinals
    );

    for (DWORD Idx = 0; Idx < OrigExports->NumberOfFunctions; Idx++)
    {
        PVOID OrigFunc = RVA2VA(
            PBYTE,
            OrigModule->BaseAddress,
            OrigFuncAddr[OrigFuncOrdinal[Idx]]
        );

        PVOID HookAddr = NULL;
        DWORD_PTR HookOffset = NULL;
        DWORD HookType = IsHooked((PBYTE)OrigFunc, &HookOffset);
        
        if (HookType == HOOK_ABSOLUTE)
        {
            HookAddr = (PVOID)(*(PDWORD)((PBYTE)OrigFunc + HookOffset));
        }
        else if (HookType == HOOK_RELATIVE)
        {
            INT JumpSize = (*(PINT)(
                (PBYTE)OrigFunc + HookOffset));

            DWORD_PTR RelativeAddr = (DWORD_PTR(
                (PBYTE)OrigFunc + HookOffset + 4));

            HookAddr = (PVOID)(RelativeAddr + JumpSize);
        }
        else continue;

        if (IsHookSameModule(HookAddr, (HMODULE)OrigModule->BaseAddress)) 
            continue;

        // External hook - Unhook file
        CleanModule = (PBYTE)ReadFileWrapper(ModulePath, &CleanBufferSize);
        if (!CleanModule) return ERROR_FILE_NOT_FOUND;

        DWORD OrigTextSegmentSize;
        PVOID OrigTextSegmentAddr = GetTextSegmentInfoMapped(
            OrigModule->BaseAddress, &OrigTextSegmentSize);
        if (!OrigTextSegmentAddr || OrigTextSegmentSize == 0)
            return ERROR_FUNCTION_FAILED;

        DWORD CleanTextSegmentSize;
        PVOID CleanTextSegmentAddr = GetTextSegmentUnmapped(
            CleanModule,
            &CleanTextSegmentSize
        );

        DWORD OldProtect;
        BOOL OK = VirtualProtect(
            OrigTextSegmentAddr,
            OrigTextSegmentSize,
            PAGE_EXECUTE_READWRITE,
            &OldProtect
        );

        if (!OK) return ERROR_INVALID_PARAMETER;

        memcpy(
            OrigTextSegmentAddr, 
            CleanTextSegmentAddr, 
            OrigTextSegmentSize
        );

        OK = VirtualProtect(
            OrigTextSegmentAddr,
            OrigTextSegmentSize,
            OldProtect,
            &OldProtect
        );

        if (!OK) return ERROR_INVALID_PARAMETER;

        return TRUE;
    }
    
    return FALSE;
}


INT main()
{
    DWORD Status = ERROR_SUCCESS;
    BOOL Hooked = UnhookModule(
        (CONST PWCHAR)L"ntdll.dll", 
        (CONST PWCHAR)L"C:\\Windows\\System32\\ntdll.dll"
    );

    return Status;
}
