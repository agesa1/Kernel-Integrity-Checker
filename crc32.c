//
// crc32.c
//

#include "driver.h"

static ULONG  CrcTable[256];
static BOOLEAN CrcTableInitialized = FALSE;

VOID
Crc32BuildTable(VOID)
{
    ULONG i, j, crc;

    __try {
        if (CrcTableInitialized)
            return;

        for (i = 0; i < 256; i++) {
            crc = i;
            for (j = 0; j < 8; j++) {
                if (crc & 1)
                    crc = (crc >> 1) ^ 0xEDB88320UL;
                else
                    crc >>= 1;
            }
            CrcTable[i] = crc;
        }
        CrcTableInitialized = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        CrcTableInitialized = FALSE;
    }
}

ULONG
Crc32Compute(
    _In_reads_bytes_(Length) PVOID  Buffer,
    _In_                     SIZE_T Length)
{
    PUCHAR ptr;
    ULONG  crc = 0xFFFFFFFFUL;
    SIZE_T i;

    __try {
        if (!Buffer || Length == 0)
            return CRC32_SENTINEL;

        if (!CrcTableInitialized)
            Crc32BuildTable();

        ptr = (PUCHAR)Buffer;

        for (i = 0; i < Length; i++) {
            crc = CrcTable[(crc ^ ptr[i]) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFUL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return CRC32_SENTINEL;
    }
}

ULONG
SafeCrc32Compute(
    _In_ PVOID  Buffer,
    _In_ SIZE_T Length)
{
    ULONG result = CRC32_SENTINEL;
    PUCHAR ptr;
    SIZE_T offset;

    __try {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return CRC32_SENTINEL;
        }

        if (!Buffer || Length == 0) {
            return CRC32_SENTINEL;
        }

        if (Length > 0x10000000) {
            return CRC32_SENTINEL;
        }

        ptr = (PUCHAR)Buffer;
        if (!MmIsAddressValid(ptr)) {
            return CRC32_SENTINEL;
        }

        if (Length > PAGE_SIZE) {
            for (offset = 0; offset < Length; offset += PAGE_SIZE) {
                if (!MmIsAddressValid(ptr + offset)) {
                    return CRC32_SENTINEL;
                }
            }
        }

        if (!MmIsAddressValid(ptr + Length - 1)) {
            return CRC32_SENTINEL;
        }

        result = Crc32Compute(Buffer, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = CRC32_SENTINEL;
    }

    return result;
}
