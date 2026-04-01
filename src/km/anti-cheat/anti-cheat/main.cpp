#include "includes.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, symLink;

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(0, 0, "ANTICHEAT - Unload called\n");

    // Stop monitor thread
    g_MonitorRunning = FALSE;
    if (g_MonitorThread) {
        KeWaitForSingleObject(g_MonitorThread, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(g_MonitorThread);
        g_MonitorThread = nullptr;
    }

    if (g_CallbackHandle != nullptr) {
        DbgPrintEx(0, 0, "ANTICHEAT - Unregistering callbacks\n");
        ObUnRegisterCallbacks(g_CallbackHandle);
        g_CallbackHandle = nullptr;
        DbgPrintEx(0, 0, "ANTICHEAT - Callbacks unregistered\n");
    }
    else {
        DbgPrintEx(0, 0, "ANTICHEAT - No callback handle to unregister\n");
    }

    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\??\\AntiCheat");
    IoDeleteSymbolicLink(&sym);

    if (DriverObject->DeviceObject != nullptr)
        IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(0, 0, "ANTICHEAT - Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

    dev = RTL_CONSTANT_STRING(L"\\Device\\AntiCheat");
    symLink = RTL_CONSTANT_STRING(L"\\??\\AntiCheat");

    status = IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
    if (status != STATUS_SUCCESS)
        return status;

    status = IoCreateSymbolicLink(&symLink, &dev);
    if (status != STATUS_SUCCESS) {
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    g_MonitorRunning = TRUE;
    HANDLE hThread = nullptr;
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, MonitorThread, nullptr);
    if (NT_SUCCESS(status)) {
        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, nullptr, KernelMode,
            (PVOID*)&g_MonitorThread, nullptr);
        ZwClose(hThread);
    }

    DbgPrintEx(0, 0, "ANTICHEAT - Driver loaded\n");
    return STATUS_SUCCESS;
}