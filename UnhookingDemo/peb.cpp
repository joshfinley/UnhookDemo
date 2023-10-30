#include "peb.h"
VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL);

    if (SourceString)
    {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        __analysis_assume(Size <= MaxSize);

        if (Size > MaxSize)
            Size = MaxSize;
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

BOOLEAN
NTAPI
RtlEqualUnicodeString(
    IN CONST UNICODE_STRING* s1,
    IN CONST UNICODE_STRING* s2,
    IN BOOLEAN  CaseInsensitive)
{
    if (s1->Length != s2->Length) return FALSE;
    return !RtlCompareUnicodeString(s1, s2, CaseInsensitive);
}

LONG
NTAPI
RtlCompareUnicodeString(
    IN PCUNICODE_STRING s1,
    IN PCUNICODE_STRING s2,
    IN BOOLEAN  CaseInsensitive)
{
    unsigned int len;
    LONG ret = 0;
    LPCWSTR p1, p2;

    len = min(s1->Length, s2->Length) / sizeof(WCHAR);
    p1 = s1->Buffer;
    p2 = s2->Buffer;

    if (CaseInsensitive)
    {
        while (!ret && len--) ret = RtlpUpcaseUnicodeChar(*p1++) - RtlpUpcaseUnicodeChar(*p2++);
    }
    else
    {
        while (!ret && len--) ret = *p1++ - *p2++;
    }

    if (!ret) ret = s1->Length - s2->Length;

    return ret;
}


WCHAR NTAPI RtlpUpcaseUnicodeChar(IN WCHAR Source) 
{
    PUSHORT NlsUnicodeUpcaseTable = NULL;
    USHORT Offset;

    if (Source < 'a')
        return Source;

    if (Source <= 'z')
        return (Source - ('a' - 'A'));

    Offset = ((USHORT)Source >> 8) & 0xFF;
    Offset = NlsUnicodeUpcaseTable[Offset];

    Offset += ((USHORT)Source >> 4) & 0xF;
    Offset = NlsUnicodeUpcaseTable[Offset];

    Offset += ((USHORT)Source & 0xF);
    Offset = NlsUnicodeUpcaseTable[Offset];

    return Source + (SHORT)Offset;
}


PLDR_MODULE FindPebModule(LPCWSTR BaseDllName)
{
    PPEB pPeb = GetPeb();
    PLIST_ENTRY pFirstEntry = &pPeb->LoaderData->InMemoryOrderModuleList;

    PUNICODE_STRING pBaseDllName = new UNICODE_STRING;

    RtlInitUnicodeString(pBaseDllName, BaseDllName);

    for (
        PLIST_ENTRY pListEntry = pFirstEntry->Flink;
        pListEntry != pFirstEntry->Blink;
        pListEntry = pListEntry->Flink)
    {
        PLDR_MODULE pEntry = CONTAINING_RECORD(
            pListEntry, LDR_MODULE, InMemoryOrderModuleList);

        if (RtlEqualUnicodeString(&pEntry->BaseDllName, pBaseDllName, TRUE)) {
            return pEntry;
        }
    }

    return NULL;
}


PLDR_MODULE* EnumModules()
{
    DWORD ModuleNum = NULL;
    INT Idx = NULL;
    PLDR_MODULE* Modules = NULL;
    PPEB Peb = GetPeb();

    PLIST_ENTRY FirstEntry = &Peb->LoaderData->InMemoryOrderModuleList;

    for (
        PLIST_ENTRY ListEntry = FirstEntry->Flink;
        ListEntry != FirstEntry->Blink;
        ListEntry = ListEntry->Flink)
    {
        PLDR_MODULE Entry = CONTAINING_RECORD(
            ListEntry, LDR_MODULE, InMemoryOrderModuleList);

        ModuleNum++;
    }

    if (!ModuleNum) return NULL;

    Modules = (PLDR_MODULE*)VirtualAlloc(
        NULL,
        ModuleNum * (sizeof(PLDR_MODULE)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    for (
        PLIST_ENTRY ListEntry = FirstEntry->Flink;
        ListEntry != FirstEntry->Blink;
        ListEntry = ListEntry->Flink)
    {
        PLDR_MODULE Entry = CONTAINING_RECORD(
            ListEntry, LDR_MODULE, InMemoryOrderModuleList);

        Modules[Idx] = Entry;
        Idx++;
    }

    return Modules;
}

PPEB GetPeb()
{
    PPEB Peb = (PPEB)__readgsqword(0x60);

    if (!Peb)
        return NULL;

    return Peb;
}
