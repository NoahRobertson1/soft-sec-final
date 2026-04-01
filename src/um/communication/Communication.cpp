#include "Communication.h"
#include <windows.h>
#include <iostream>


namespace Communication {
    bool RegisterCallback() {
        HANDLE hDevice = CreateFileW(L"\\\\.\\AntiCheat", GENERIC_WRITE,
            FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cout << "Failed to create handle";
            return false;
        }

        HANDLE pid = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
        DWORD bytesReturned = 0;

        BOOL success = DeviceIoControl(hDevice, IOCTL_ANTI_CHEAT_ENALBE_OBREGISTERCALLBACKS, &pid,
            sizeof(pid), nullptr, 0, &bytesReturned, nullptr);

        return success;
    }
} // Communication