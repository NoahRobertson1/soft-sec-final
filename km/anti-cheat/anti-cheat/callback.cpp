#include "includes.h"

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    DbgPrintEx(0, 0, "ANTICHEAT - Caught Callback");

    if (Info->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (!Info->Parameters)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProcess = (PEPROCESS)Info->Object;

    DbgPrintEx(0, 0, "ANTICHEAT - Target PID: %llu, Protected PID: %llu",
        (ULONG64)PsGetProcessId(targetProcess),
        (ULONG64)g_ProtectedPID);

    if (PsGetProcessId(targetProcess) != g_ProtectedPID) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK mask = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~mask;
    }
    else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~mask;
    }

    DbgPrintEx(0, 0, "Stripped handle permisions for PID: %d", g_ProtectedPID);

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterCallbacks() {
    OB_OPERATION_REGISTRATION opReg = {};
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = OnPreOpenProcess;
    opReg.PostOperation = nullptr;

    OB_CALLBACK_REGISTRATION cbReg = {};
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.OperationRegistration = &opReg;
    RtlInitUnicodeString(&cbReg.Altitude, L"321000");

    return ObRegisterCallbacks(&cbReg, &g_CallbackHandle);
}