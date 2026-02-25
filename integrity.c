//
// integrity.c
//

#include "driver.h"

PINTEGRITY_CONTEXT g_IntegrityCtx = NULL;

//
// Validate memory range page by page
//
BOOLEAN
IsSafeToRead(
    _In_ PVOID  Address,
    _In_ SIZE_T Size)
{
    PUCHAR base   = (PUCHAR)Address;
    volatile UCHAR dummy;
    SIZE_T offset = 0;

    __try {
        if (!Address || Size == 0)
            return FALSE;

        if (((ULONG_PTR)Address & 0xFFF) + Size > PAGE_SIZE * 1024) {
            while (offset < Size) {
                if (!MmIsAddressValid((PVOID)(base + offset))) {
                    return FALSE;
                }
                dummy = base[offset];
                offset += PAGE_SIZE;
            }
            if (!MmIsAddressValid((PVOID)(base + Size - 1))) {
                return FALSE;
            }
            dummy = base[Size - 1];
        }
        else {
            if (!MmIsAddressValid(Address)) {
                return FALSE;
            }
            for (offset = 0; offset < Size; offset += PAGE_SIZE) {
                if (!MmIsAddressValid((PVOID)(base + offset))) {
                    return FALSE;
                }
                dummy = base[offset];
            }
            if (Size > 0 && !MmIsAddressValid((PVOID)(base + Size - 1))) {
                return FALSE;
            }
            dummy = base[Size - 1];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("[KIM] Memory access violation at %p (size: %zu, code: 0x%08X)\n",
                 Address, Size, GetExceptionCode()));
        return FALSE;
    }

    return TRUE;
}

//
// Parse PE headers and locate .text section
//
PVOID
GetTextSectionBase(
    _In_  PVOID   ImageBase,
    _Out_ PSIZE_T TextSize)
{
    PIMAGE_DOS_HEADER     dosHdr;
    PIMAGE_NT_HEADERS     ntHdr;
    PIMAGE_SECTION_HEADER sec;
    USHORT                i;
    PVOID                 result = NULL;

    __try {
        *TextSize = 0;

        if (!ImageBase || !MmIsAddressValid(ImageBase))
            return NULL;

        if (!IsSafeToRead(ImageBase, sizeof(IMAGE_DOS_HEADER)))
            return NULL;

        dosHdr = (PIMAGE_DOS_HEADER)ImageBase;
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }

        if (dosHdr->e_lfanew > 0x1000 || dosHdr->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
            return NULL;
        }

        ntHdr = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHdr->e_lfanew);
        if (!IsSafeToRead(ntHdr, sizeof(IMAGE_NT_HEADERS))) {
            return NULL;
        }

        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }

        if (ntHdr->FileHeader.NumberOfSections == 0 || 
            ntHdr->FileHeader.NumberOfSections > 96) {
            return NULL;
        }

        sec = IMAGE_FIRST_SECTION(ntHdr);
        if (!IsSafeToRead(sec, sizeof(IMAGE_SECTION_HEADER) * ntHdr->FileHeader.NumberOfSections)) {
            return NULL;
        }

        for (i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
            if (RtlCompareMemory(sec[i].Name, ".text", 5) == 5) {
                PVOID textVA = (PVOID)((PUCHAR)ImageBase + sec[i].VirtualAddress);
                SIZE_T textSz = (SIZE_T)sec[i].Misc.VirtualSize;

                if (textSz == 0 || textSz > 0x10000000) {
                    return NULL;
                }

                if (!MmIsAddressValid(textVA)) {
                    return NULL;
                }

                if (!IsSafeToRead(textVA, min(textSz, PAGE_SIZE))) {
                    return NULL;
                }

                *TextSize = textSz;
                result = textVA;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *TextSize = 0;
        return NULL;
    }

    return result;
}

//
// Enumerate system modules and compute baseline CRC
//
NTSTATUS
EnumerateAndBaselineModules(
    _In_ PINTEGRITY_CONTEXT Ctx)
{
    NTSTATUS                   status;
    ULONG                      bufferSize = 0;
    PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
    ULONG                      i;

    static const PCHAR watchList[] = {
        "ntoskrnl.exe",
        "hal.dll",
        "ci.dll",
        "ksecdd.sys",
        "cng.sys",
        "tcpip.sys",
        NULL
    };

    __try {
        if (!Ctx) {
            return STATUS_INVALID_PARAMETER;
        }

        status = ZwQuerySystemInformation(
            SystemModuleInformation, NULL, 0, &bufferSize);

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return status;
        }

        bufferSize += 4096;

        moduleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG);

        if (!moduleInfo) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(moduleInfo, bufferSize);

        status = ZwQuerySystemInformation(
            SystemModuleInformation, moduleInfo, bufferSize, &bufferSize);

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(moduleInfo, POOL_TAG);
            return status;
        }

        KdPrint(("[KIM] Scanning %lu modules\n", moduleInfo->Count));

        Ctx->ModuleCount = 0;

        for (i = 0; i < moduleInfo->Count && Ctx->ModuleCount < MAX_MONITORED_MODULES; i++) {
            __try {
                PSYSTEM_MODULE_ENTRY entry = &moduleInfo->Modules[i];
                PCHAR fileName;
                ULONG j = 0;

                if (entry->OffsetToFileName >= sizeof(entry->FullPathName)) {
                    continue;
                }

                fileName = (PCHAR)(entry->FullPathName + entry->OffsetToFileName);

                while (watchList[j]) {
                    if (_stricmp(fileName, watchList[j]) == 0) {
                        PMODULE_INTEGRITY_ENTRY mEntry = &Ctx->Modules[Ctx->ModuleCount];

                        RtlZeroMemory(mEntry, sizeof(MODULE_INTEGRITY_ENTRY));

                        status = RtlStringCchPrintfW(
                            mEntry->ModuleName,
                            ARRAYSIZE(mEntry->ModuleName),
                            L"%S", fileName);

                        if (!NT_SUCCESS(status)) {
                            j++;
                            continue;
                        }

                        if (!entry->ImageBase || entry->ImageSize == 0 || entry->ImageSize > 0x10000000) {
                            j++;
                            continue;
                        }

                        mEntry->BaseAddress = entry->ImageBase;
                        mEntry->ImageSize = (SIZE_T)entry->ImageSize;

                        if (!MmIsAddressValid(mEntry->BaseAddress) ||
                            !IsSafeToRead(mEntry->BaseAddress, PAGE_SIZE)) {
                            j++;
                            continue;
                        }

                        mEntry->TextBase = GetTextSectionBase(
                            mEntry->BaseAddress, &mEntry->TextSize);

                        if (!mEntry->TextBase || mEntry->TextSize == 0) {
                            mEntry->TextBase = mEntry->BaseAddress;
                            mEntry->TextSize = mEntry->ImageSize;

                            if (!IsSafeToRead(mEntry->TextBase, min(mEntry->TextSize, PAGE_SIZE * 4))) {
                                j++;
                                continue;
                            }
                        }

                        mEntry->OriginalCRC32 = SafeCrc32Compute(
                            mEntry->TextBase, mEntry->TextSize);

                        if (mEntry->OriginalCRC32 == CRC32_SENTINEL) {
                            j++;
                            continue;
                        }

                        mEntry->BaselineValid = TRUE;
                        mEntry->IsCompromised = FALSE;

                        KdPrint(("[KIM] %s: base=%p text=%p size=%zu crc=0x%08X\n",
                                 fileName,
                                 mEntry->BaseAddress,
                                 mEntry->TextBase,
                                 mEntry->TextSize,
                                 mEntry->OriginalCRC32));

                        Ctx->ModuleCount++;
                        break;
                    }
                    j++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }

        ExFreePoolWithTag(moduleInfo, POOL_TAG);

        KdPrint(("[KIM] Monitoring %lu modules\n", Ctx->ModuleCount));
        return Ctx->ModuleCount > 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (moduleInfo) {
            ExFreePoolWithTag(moduleInfo, POOL_TAG);
        }
        return STATUS_UNSUCCESSFUL;
    }
}

//
// Check module integrity
//
NTSTATUS
CheckModuleIntegrity(
    _In_ PMODULE_INTEGRITY_ENTRY Entry)
{
    ULONG currentCRC;
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_UNSUCCESSFUL;
        }

        if (!Entry || !Entry->BaselineValid) {
            return STATUS_UNSUCCESSFUL;
        }

        if (!Entry->TextBase || !Entry->TextSize) {
            return STATUS_UNSUCCESSFUL;
        }

        if (!MmIsAddressValid(Entry->TextBase)) {
            return STATUS_UNSUCCESSFUL;
        }

        if (!IsSafeToRead(Entry->TextBase, Entry->TextSize)) {
            return STATUS_UNSUCCESSFUL;
        }

        currentCRC = SafeCrc32Compute(Entry->TextBase, Entry->TextSize);

        if (currentCRC == CRC32_SENTINEL) {
            return STATUS_UNSUCCESSFUL;
        }

        if (currentCRC != Entry->OriginalCRC32) {
            ReportViolation(Entry, currentCRC);
            Entry->IsCompromised = TRUE;
            status = STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

//
// Report integrity violation
//
VOID
ReportViolation(
    _In_ PMODULE_INTEGRITY_ENTRY Entry,
    _In_ ULONG                   CurrentCRC)
{
    KdPrint(("[KIM] !!! INTEGRITY VIOLATION !!!\n"));
    KdPrint(("[KIM] Module: %ws\n", Entry->ModuleName));
    KdPrint(("[KIM] Base: %p Text: %p Size: %zu\n", 
             Entry->BaseAddress, Entry->TextBase, Entry->TextSize));
    KdPrint(("[KIM] Expected CRC: 0x%08X Current: 0x%08X Delta: 0x%08X\n",
             Entry->OriginalCRC32, CurrentCRC, Entry->OriginalCRC32 ^ CurrentCRC));
}

//
// Integrity monitoring worker thread
//
VOID
IntegrityWorkerThread(
    _In_ PVOID Context)
{
    PINTEGRITY_CONTEXT ctx = (PINTEGRITY_CONTEXT)Context;
    LARGE_INTEGER      delay;
    ULONG              violations;
    ULONG              i;

    __try {
        if (!ctx) {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            return;
        }

        KdPrint(("[KIM] Worker thread started\n"));

        KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY - 2);

        while (ctx->Running) {
            __try {
                delay.QuadPart = -(10000LL * (LONGLONG)CHECK_INTERVAL_MS);
                KeDelayExecutionThread(KernelMode, FALSE, &delay);

                if (!ctx->Running)
                    break;

                violations = 0;

                for (i = 0; i < ctx->ModuleCount; i++) {
                    __try {
                        if (!ctx->Running)
                            break;

                        if (!NT_SUCCESS(CheckModuleIntegrity(&ctx->Modules[i]))) {
                            violations++;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        violations++;
                    }
                }

                if (violations > 0) {
                    KdPrint(("[KIM] WARNING: %lu integrity violations detected\n", violations));
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }

        KdPrint(("[KIM] Worker thread terminated\n"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}
