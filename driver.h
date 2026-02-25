#pragma once

#include <ntddk.h>
#include <wdm.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define DRIVER_TAG              'KICM'
#define POOL_TAG                DRIVER_TAG
#define MAX_MONITORED_MODULES   16
#define CHECK_INTERVAL_MS       5000
#define CRC32_SENTINEL          0xDEADC0DEul
#define MAX_WAIT_SECONDS        10

VOID PteLog(_In_ PCSTR Format, ...);

#undef KdPrint
#define KdPrint(x) PteLog x

typedef struct _MODULE_INTEGRITY_ENTRY {
    WCHAR   ModuleName[64];
    PVOID   BaseAddress;
    SIZE_T  ImageSize;
    PVOID   TextBase;       // .text section başlangıcı
    SIZE_T  TextSize;       // .text section boyutu
    ULONG   OriginalCRC32;
    BOOLEAN IsCompromised;
    BOOLEAN BaselineValid;
} MODULE_INTEGRITY_ENTRY, *PMODULE_INTEGRITY_ENTRY;

typedef struct _INTEGRITY_CONTEXT {
    MODULE_INTEGRITY_ENTRY  Modules[MAX_MONITORED_MODULES];
    ULONG                   ModuleCount;
    volatile BOOLEAN        Running;
    KEVENT                  WakeEvent;
    HANDLE                  ThreadHandle;
    PETHREAD                ThreadObject;
} INTEGRITY_CONTEXT, *PINTEGRITY_CONTEXT;

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG               Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define SystemModuleInformation 11

NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
    IN  ULONG   SystemInformationClass,
    OUT PVOID   SystemInformation,
    IN  ULONG   SystemInformationLength,
    OUT PULONG  ReturnLength OPTIONAL
);

VOID  Crc32BuildTable(VOID);
ULONG Crc32Compute(_In_reads_bytes_(Length) PVOID Buffer, _In_ SIZE_T Length);
ULONG SafeCrc32Compute(_In_ PVOID Buffer, _In_ SIZE_T Length);

BOOLEAN  IsSafeToRead(_In_ PVOID Address, _In_ SIZE_T Size);
PVOID    GetTextSectionBase(_In_ PVOID ImageBase, _Out_ PSIZE_T TextSize);
NTSTATUS EnumerateAndBaselineModules(_In_ PINTEGRITY_CONTEXT Ctx);
NTSTATUS CheckModuleIntegrity(_In_ PMODULE_INTEGRITY_ENTRY Entry);
VOID     ReportViolation(_In_ PMODULE_INTEGRITY_ENTRY Entry, _In_ ULONG CurrentCRC);
VOID     IntegrityWorkerThread(_In_ PVOID Context);

extern PINTEGRITY_CONTEXT g_IntegrityCtx;
