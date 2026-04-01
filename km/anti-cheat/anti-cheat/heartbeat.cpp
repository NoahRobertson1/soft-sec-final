#include "heartbeat.h"

VOID MonitorThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    while (g_MonitorRunning) {
        if (g_ProtectedPID != nullptr) {
            PEPROCESS process = nullptr;
            NTSTATUS status = PsLookupProcessByProcessId(g_ProtectedPID, &process);

            if (!NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "ANTICHEAT - Protected process exited, cleaning up\n");

                if (g_CallbackHandle != nullptr) {
                    ObUnRegisterCallbacks(g_CallbackHandle);
                    g_CallbackHandle = nullptr;
                }
                g_ProtectedPID = nullptr;
            }
            else {
                ObDereferenceObject(process);
            }
        }

        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; // 1 second
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}