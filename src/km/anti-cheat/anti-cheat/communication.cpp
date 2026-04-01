#include "includes.h"

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	return STATUS_SUCCESS;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_ANTI_CHEAT_ENALBE_OBREGISTERCALLBACKS: {
		DbgPrintEx(0, 0, "ANTICHEAT - Recieved IOCTL");

		if (g_CallbackHandle != nullptr) {
			status = STATUS_ALREADY_REGISTERED;
			break;
		}

		if (stack->Parameters.DeviceIoControl.Type3InputBuffer == nullptr ||
			stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		g_ProtectedPID = *(HANDLE*)stack->Parameters.DeviceIoControl.Type3InputBuffer;

		status = RegisterCallbacks();

		if (status != STATUS_SUCCESS) {
			g_ProtectedPID = nullptr;
		}

		DbgPrintEx(0, 0, "ANTICHEAT - Registered callback, status 0x%X", status);
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}