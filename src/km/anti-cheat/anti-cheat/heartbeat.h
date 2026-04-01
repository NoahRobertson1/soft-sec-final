#pragma once
#include <ntifs.h>
#include "callback.h"

inline PKTHREAD g_MonitorThread = nullptr;
inline BOOLEAN g_MonitorRunning = FALSE;

VOID MonitorThread(PVOID Context);