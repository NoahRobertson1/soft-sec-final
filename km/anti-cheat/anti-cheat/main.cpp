#include "includes.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, symLink;

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrintEx(0, 0, "ANTICHEAT - Unload called\n");

	if (g_CallbackHandle != nullptr) {
		DbgPrintEx(0, 0, "ANTICHEAT - Unregistering callbacks\n");
		ObUnRegisterCallbacks(g_CallbackHandle);
		g_CallbackHandle = nullptr;
		DbgPrintEx(0, 0, "ANTICHEAT - Callbacks unregistered\n");
	}
	else {
		DbgPrintEx(0, 0, "ANTICHEAT - No callback handle to unregister\n");
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\AntiCheat");
	IoDeleteSymbolicLink(&symLink);

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
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = IoCreateSymbolicLink(&symLink, &dev);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	return STATUS_SUCCESS;
}