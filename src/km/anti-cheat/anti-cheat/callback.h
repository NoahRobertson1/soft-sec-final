#pragma once
#include <ntifs.h>

#define PROCESS_VM_READ        0x0010
#define PROCESS_VM_WRITE       0x0020
#define PROCESS_VM_OPERATION   0x0008
#define PROCESS_ALL_ACCESS     0x1FFFFF

inline PVOID g_CallbackHandle = nullptr;
inline PVOID g_ProtectedPID = nullptr;

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
NTSTATUS RegisterCallbacks();