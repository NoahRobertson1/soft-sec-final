#include "Protection.h"
#include "../util/Util.h"
#include "../communication/Communication.h"

#include <windows.h>
#include <ntdef.h>
#include <winternl.h>
#include <thread>
#include <cstring>
extern "C" {
#include "aes.h"
}
#include <psapi.h>
#include <algorithm>
#include <tlhelp32.h>

namespace Protection {
    namespace Scanner {
        std::wstring DevicePathToDrivePath(const std::wstring& devicePath) {
            WCHAR drives[512] = {};
            GetLogicalDriveStringsW(512, drives);

            WCHAR* drive = drives;
            while (*drive) {
                WCHAR driveLetter[3] = { drive[0], drive[1], 0 };
                WCHAR deviceName[MAX_PATH] = {};
                QueryDosDeviceW(driveLetter, deviceName, MAX_PATH);

                std::wstring devName(deviceName);
                if (devicePath.find(devName) == 0) {
                    return std::wstring(driveLetter) + devicePath.substr(devName.size());
                }
                drive += wcslen(drive) + 1;
            }
            return devicePath;
        }

        std::vector<std::wstring> GetMappedModulePaths() {
            std::vector<std::wstring> paths;
            HANDLE hProcess = GetCurrentProcess();
            PBYTE addr = nullptr;
            MEMORY_BASIC_INFORMATION mbi = {};

            while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
                if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT) {
                    WCHAR path[MAX_PATH] = {};
                    if (GetMappedFileNameW(hProcess, addr, path, MAX_PATH) > 0) {
                        std::wstring normalPath = DevicePathToDrivePath(std::wstring(path));
                        if (std::find(paths.begin(), paths.end(), normalPath) == paths.end())
                            paths.push_back(normalPath);
                    }
                }
                addr += mbi.RegionSize;
            }
            return paths;
        }
        std::vector<uintptr_t> GetSuspiciousRegions() {
            std::vector<uintptr_t> suspicious;
            PBYTE addr = nullptr;
            MEMORY_BASIC_INFORMATION mbi = {};

            while (true) {
                if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
                    break;

                bool isExecutable = (mbi.Protect == PAGE_EXECUTE ||
                                     mbi.Protect == PAGE_EXECUTE_READ ||
                                     mbi.Protect == PAGE_EXECUTE_READWRITE ||
                                     mbi.Protect == PAGE_EXECUTE_WRITECOPY);

                if (mbi.State == MEM_COMMIT && isExecutable && mbi.Type == MEM_PRIVATE) {
                    suspicious.push_back((uintptr_t)addr);
                }

                if (mbi.RegionSize == 0)
                    break;

                addr += mbi.RegionSize;
            }
            return suspicious;
        }

        void ScanPrivateRegions(uintptr_t base, uintptr_t end) {
            PBYTE addr = nullptr;
            MEMORY_BASIC_INFORMATION mbi = {};

            while (VirtualQuery(addr, &mbi, sizeof(mbi)) != 0) {
                if (mbi.RegionSize == 0)
                    break;

                // Only process committed, executable, private regions
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                    bool isExecutable = (mbi.Protect == PAGE_EXECUTE ||
                                         mbi.Protect == PAGE_EXECUTE_READ ||
                                         mbi.Protect == PAGE_EXECUTE_READWRITE ||
                                         mbi.Protect == PAGE_EXECUTE_WRITECOPY);

                    if (isExecutable) {
                        uintptr_t regionAddr = (uintptr_t)addr;
                        if (regionAddr < base || regionAddr > end) {
                            std::wstring message = L"Manual mapped module detected - suspicious executable region at: 0x" + std::to_wstring(regionAddr);
                            MessageBoxW(nullptr, message.c_str(), L"Anti Cheat", MB_OK | MB_ICONWARNING);
                            std::exit(1);
                        }
                    }
                }

                addr += mbi.RegionSize;
            }
        }

        void ScanVAD() {
            // Build PEB module list
            std::vector<std::wstring> pebModules;
            PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
            auto entry = peb->Ldr->InMemoryOrderModuleList.Flink;
            auto head  = &peb->Ldr->InMemoryOrderModuleList;

            while (entry != head) {
                auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0) {
                    pebModules.emplace_back(mod->FullDllName.Buffer,
                        mod->FullDllName.Length / sizeof(WCHAR));
                }
                entry = entry->Flink;
            }

            // Scan MEM_IMAGE regions against PEB
            auto vadPaths = GetMappedModulePaths();
            for (auto& vadPath : vadPaths) {
                std::wstring windowsDir = L"C:\\Windows\\";
                if (vadPath.size() >= windowsDir.size() &&
                    _wcsicmp(vadPath.substr(0, windowsDir.size()).c_str(), windowsDir.c_str()) == 0)
                    continue;

                bool found = false;
                for (auto& pebPath : pebModules) {
                    auto vadName = vadPath.substr(vadPath.find_last_of(L'\\') + 1);
                    auto pebName = pebPath.substr(pebPath.find_last_of(L'\\') + 1);
                    if (_wcsicmp(vadName.c_str(), pebName.c_str()) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    std::wstring message = L"Manually mapped module detected: " + vadPath;
                    MessageBoxW(nullptr, message.c_str(), L"Anti Cheat", MB_OK | MB_ICONWARNING);
                    std::exit(1);
                }
            }

            HMODULE hSelf = GetModuleHandleA(nullptr);
            MODULEINFO mi = {};
            GetModuleInformation(GetCurrentProcess(), hSelf, &mi, sizeof(mi));
            uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
            uintptr_t end  = base + mi.SizeOfImage;

            ScanPrivateRegions(base, end);
        }

        void ScanThreads() {
            static fnNtQueryInformationThread NtQueryInformationThread =
                (fnNtQueryInformationThread)GetProcAddress(
                    GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

            if (!NtQueryInformationThread) return;

            DWORD myPID = GetCurrentProcessId();
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap == INVALID_HANDLE_VALUE) return;

            THREADENTRY32 te = { sizeof(te) };
            if (!Thread32First(hSnap, &te)) {
                CloseHandle(hSnap);
                return;
            }

            do {
                if (te.th32OwnerProcessID != myPID) continue;

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThread) continue;

                PVOID startAddr = nullptr;
                NtQueryInformationThread(hThread, (THREADINFOCLASS)9,
                    &startAddr, sizeof(startAddr), nullptr);

                if (startAddr) {
                    MEMORY_BASIC_INFORMATION mbi = {};
                    VirtualQuery(startAddr, &mbi, sizeof(mbi));

                    if (mbi.Type != MEM_IMAGE) {
                        std::wstring message =
                            L"Manual mapped module detected - suspicious thread " +
                            std::to_wstring(te.th32ThreadID) +
                            L" start address: " +
                            std::to_wstring(reinterpret_cast<uintptr_t>(startAddr));

                        MessageBoxW(nullptr, message.c_str(), L"Anti Cheat", MB_OK | MB_ICONWARNING);
                        std::exit(1);
                    }
                }

                CloseHandle(hThread);
            } while (Thread32Next(hSnap, &te));

            CloseHandle(hSnap);
        }

        void SetUpWhitelist() {
            PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
            auto entry = peb->Ldr->InMemoryOrderModuleList.Flink;
            auto head  = &peb->Ldr->InMemoryOrderModuleList;

            while (entry != head) {
                auto mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (mod->FullDllName.Buffer == nullptr || mod->FullDllName.Length == 0) {
                    entry = entry->Flink;
                    continue;
                }

                std::wstring fullPath(mod->FullDllName.Buffer,
                    mod->FullDllName.Length / sizeof(WCHAR));

                size_t pos = fullPath.find_last_of(L'\\');
                std::wstring name = (pos != std::wstring::npos)
                    ? fullPath.substr(pos + 1)
                    : fullPath;

                whitelist.push_back(name);
                entry = entry->Flink;
            }
        }

        bool IsModuleWhitelisted(const std::wstring& fullPath) {
            std::wstring windowsDir = L"C:\\Windows\\";
            if (fullPath.size() >= windowsDir.size())
                if (_wcsicmp(fullPath.substr(0, windowsDir.size()).c_str(), windowsDir.c_str()) == 0) {
                    return true;
                }

            size_t pos = fullPath.find_last_of(L'\\');
            std::wstring name = (pos != std::wstring::npos)
                ? fullPath.substr(pos + 1)
                : fullPath;

            for (auto& w : whitelist) {
                if (_wcsicmp(name.c_str(), w.c_str()) == 0) {
                    return true;
                }
            }

            return false;
        }

        void ScanLoadedModules() {
            PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
            auto entry = peb->Ldr->InMemoryOrderModuleList.Flink;
            auto head  = &peb->Ldr->InMemoryOrderModuleList;

            while (entry != head) {
                auto mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                // Add the null check back
                if (mod->FullDllName.Buffer == nullptr || mod->FullDllName.Length == 0) {
                    entry = entry->Flink;
                    continue;
                }

                std::wstring fullPath(mod->FullDllName.Buffer,
                    mod->FullDllName.Length / sizeof(WCHAR));

                if (!IsModuleWhitelisted(fullPath)) {
                    std::wstring message = L"Unknown module: " + fullPath;
                    MessageBoxW(nullptr, message.c_str(), L"Anti Cheat", MB_OK | MB_ICONWARNING);
                    std::exit(1);
                }

                entry = entry->Flink;
            }
        }

        void PEBScanner() {
            SetUpWhitelist();
            while (true) {
                ScanLoadedModules();
                Sleep(500);
            }
        }

        void FullScanner() {
            SetUpWhitelist();
            while (true) {
                ScanLoadedModules();
                ScanVAD();
                ScanThreads();
                Sleep(500);
            }
        }
    } // Scanner

    namespace Level2 {
        const char* EncryptedPlayer::GetName() const {
            return _name;
        }

        int EncryptedPlayer::GetHealth() const {
            return Decrypt(_health);
        }

        void EncryptedPlayer::SetHealth(const int health) {
            _health = Encrypt(health);
        }

        void EncryptedPlayer::AppyHeal() {
            _health = Encrypt(Decrypt(_health) + 10);
        }

        void EncryptedPlayer::ApplyDamage() {
            _health = Encrypt(Decrypt(_health) - 10);
        }

        void Start() {
            std::thread(Scanner::PEBScanner).detach();

            auto player = new EncryptedPlayer("Player2", 100);

            bool initialRender = true;

            while (true) {
                bool change=true;

                if (initialRender) {
                    Util::render(player->GetName(), player->GetHealth());
                    initialRender = false;
                }

                if (GetAsyncKeyState(VK_SPACE) & 1) {
                    player->AppyHeal();
                }
                else if (GetAsyncKeyState(VK_SHIFT) & 1) {
                    player->ApplyDamage();
                }
                else {
                    change=false;
                }

                if (change==true) {
                    Util::render(player->GetName(), player->GetHealth());
                }
                Sleep(1);
            }
        }
    } // Level2

    namespace Level3 {
        void EncryptedPlayer::InitCrypto() {
            srand((unsigned)time(nullptr));
            for (int i = 0; i < 16; i++) {
                _key[i] = rand() & 0xFF;
                _iv[i]  = rand() & 0xFF;
            }
        }

        int EncryptedPlayer::Encrypt(int val) const {
            uint8_t buf[16] = {};
            memcpy(buf, &val, sizeof(val));

            uint8_t iv_copy[16];
            memcpy(iv_copy, _iv, 16);

            AES_ctx ctx;
            AES_init_ctx_iv(&ctx, _key, iv_copy);
            AES_CTR_xcrypt_buffer(&ctx, buf, sizeof(buf));

            int result = 0;
            memcpy(&result, buf, sizeof(result));
            return result;
        }

        int EncryptedPlayer::Decrypt(int val) const {
            return Encrypt(val);
        }

        EncryptedPlayer::EncryptedPlayer(const char* name, const int health)
            : _name(name), _health(0) {
            InitCrypto();
            _health = Encrypt(health);
        }

        const char* EncryptedPlayer::GetName() const {
            return _name;
        }

        int EncryptedPlayer::GetHealth() const {
            return Decrypt(_health);
        }

        void EncryptedPlayer::SetHealth(const int health) {
            _health = Encrypt(health);
        }

        void EncryptedPlayer::AppyHeal() {
            _health = Encrypt(Decrypt(_health) + 10);
        }

        void EncryptedPlayer::ApplyDamage() {
            _health = Encrypt(Decrypt(_health) - 10);
        }

        void Start() {
            Communication::RegisterCallback();
            std::thread(Scanner::FullScanner).detach();

            auto player = new EncryptedPlayer("Player3", 100);

            bool initialRender = true;

            while (true) {
                bool change=true;

                if (initialRender) {
                    Util::render(player->GetName(), player->GetHealth());
                    initialRender = false;
                }

                if (GetAsyncKeyState(VK_SPACE) & 1) {
                    player->AppyHeal();
                }
                else if (GetAsyncKeyState(VK_SHIFT) & 1) {
                    player->ApplyDamage();
                }
                else {
                    change=false;
                }

                if (change==true) {
                    Util::render(player->GetName(), player->GetHealth());
                }
                Sleep(1);
            }
        }
    } // Level3
} // Protection