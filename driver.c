//
// driver.c
//

#include "driver.h"

DRIVER_UNLOAD DriverUnload;
DRIVER_INITIALIZE DriverEntry;

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    __try {
        KdPrint(("[KIM] Unloading driver...\n"));

        if (!g_IntegrityCtx) {
            return;
        }

        InterlockedExchange((LONG volatile*)&g_IntegrityCtx->Running, FALSE);

        if (g_IntegrityCtx->ThreadObject) {
            LARGE_INTEGER timeout;
            NTSTATUS waitStatus;

            timeout.QuadPart = -(10000LL * 1000LL * MAX_WAIT_SECONDS);

            __try {
                waitStatus = KeWaitForSingleObject(
                    g_IntegrityCtx->ThreadObject,
                    Executive,
                    KernelMode,
                    FALSE,
                    &timeout);

                if (waitStatus == STATUS_TIMEOUT) {
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }

            ObDereferenceObject(g_IntegrityCtx->ThreadObject);
            g_IntegrityCtx->ThreadObject = NULL;
        }

        if (g_IntegrityCtx->ThreadHandle) {
            __try {
                ZwClose(g_IntegrityCtx->ThreadHandle);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
            g_IntegrityCtx->ThreadHandle = NULL;
        }

        ExFreePoolWithTag(g_IntegrityCtx, POOL_TAG);
        g_IntegrityCtx = NULL;

        KdPrint(("[KIM] Driver unloaded\n"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS          status;
    OBJECT_ATTRIBUTES objAttr;

    UNREFERENCED_PARAMETER(RegistryPath);

    __try {
        KdPrint(("[KIM] ================================================\n"));
        KdPrint(("[KIM] Kernel Integrity Monitor v1.0\n"));
        KdPrint(("[KIM] ================================================\n"));

        DriverObject->DriverUnload = DriverUnload;

        g_IntegrityCtx = (PINTEGRITY_CONTEXT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(INTEGRITY_CONTEXT),
            POOL_TAG);

        if (!g_IntegrityCtx) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(g_IntegrityCtx, sizeof(INTEGRITY_CONTEXT));
        g_IntegrityCtx->Running      = TRUE;
        g_IntegrityCtx->ThreadHandle = NULL;
        g_IntegrityCtx->ThreadObject = NULL;

        KeInitializeEvent(&g_IntegrityCtx->WakeEvent, NotificationEvent, FALSE);

        status = EnumerateAndBaselineModules(g_IntegrityCtx);

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(g_IntegrityCtx, POOL_TAG);
            g_IntegrityCtx = NULL;
            return status;
        }

        InitializeObjectAttributes(
            &objAttr,
            NULL,
            OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = PsCreateSystemThread(
            &g_IntegrityCtx->ThreadHandle,
            THREAD_ALL_ACCESS,
            &objAttr,
            NULL,
            NULL,
            IntegrityWorkerThread,
            (PVOID)g_IntegrityCtx);

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(g_IntegrityCtx, POOL_TAG);
            g_IntegrityCtx = NULL;
            return status;
        }

        status = ObReferenceObjectByHandle(
            g_IntegrityCtx->ThreadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&g_IntegrityCtx->ThreadObject,
            NULL);

        if (!NT_SUCCESS(status)) {
            g_IntegrityCtx->ThreadObject = NULL;
        }

        KdPrint(("[KIM] ================================================\n"));
        KdPrint(("[KIM] Status: ACTIVE\n"));
        KdPrint(("[KIM] Modules: %lu | Interval: %dms\n", 
                 g_IntegrityCtx->ModuleCount, CHECK_INTERVAL_MS));
        KdPrint(("[KIM] ================================================\n"));

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_IntegrityCtx) {
            if (g_IntegrityCtx->ThreadHandle) {
                ZwClose(g_IntegrityCtx->ThreadHandle);
            }
            ExFreePoolWithTag(g_IntegrityCtx, POOL_TAG);
            g_IntegrityCtx = NULL;
        }
        
        return STATUS_UNSUCCESSFUL;
    }
}

VOID PteLog(_In_ PCSTR Format, ...)
{
    va_list argList;
    CHAR buffer[1024];
    NTSTATUS status;
    size_t len = 0;
    LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS timeFields;

    __try {
        KeQuerySystemTime(&systemTime);
        ExSystemTimeToLocalTime(&systemTime, &localTime);
        RtlTimeToTimeFields(&localTime, &timeFields);

        status = RtlStringCbPrintfA(buffer, sizeof(buffer),
            "[%04d-%02d-%02d %02d:%02d:%02d] ",
            timeFields.Year, timeFields.Month, timeFields.Day,
            timeFields.Hour, timeFields.Minute, timeFields.Second);

        if (!NT_SUCCESS(status)) {
            return;
        }

        RtlStringCbLengthA(buffer, sizeof(buffer), &len);

        va_start(argList, Format);
        status = RtlStringCbVPrintfA(buffer + len, sizeof(buffer) - len, Format, argList);
        va_end(argList);

        if (!NT_SUCCESS(status)) {
            return;
        }

        RtlStringCbLengthA(buffer, sizeof(buffer), &len);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", buffer);

        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            UNICODE_STRING uniName;
            OBJECT_ATTRIBUTES objAttr;
            HANDLE handle = NULL;
            IO_STATUS_BLOCK ioStatusBlock;

            __try {
                RtlInitUnicodeString(&uniName, L"\\??\\C:\\pte_log.txt");
                InitializeObjectAttributes(&objAttr, &uniName,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    NULL, NULL);

                status = ZwCreateFile(&handle,
                    FILE_APPEND_DATA | SYNCHRONIZE,
                    &objAttr, &ioStatusBlock, NULL,
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN_IF,
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
                    NULL, 0);

                if (NT_SUCCESS(status) && handle) {
                    ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, 
                        buffer, (ULONG)len, NULL, NULL);
                    ZwClose(handle);
                    handle = NULL;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (handle) {
                    ZwClose(handle);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
