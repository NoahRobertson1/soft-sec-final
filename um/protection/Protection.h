#ifndef SOFT_SEC_FINAL_PROTECTION_H
#define SOFT_SEC_FINAL_PROTECTION_H

#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <wincrypt.h>

namespace Protection {
    namespace Scanner {
        inline std::vector<std::wstring> whitelist = {};

        typedef enum _THREADINFOCLASS {
            ThreadBasicInformation = 0,
            ThreadQuerySetWin32StartAddress = 9,
            ThreadTimes = 8,
        } THREADINFOCLASS;

        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } PEB_LDR_DATA, *PPEB_LDR_DATA;

        typedef struct _PEB {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PPEB_LDR_DATA Ldr;
            // Add more fields if needed
        } PEB, *PPEB;

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR Buffer;
        } UNICODE_STRING;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifdef _M_X64
#define NtCurrentTeb() ((struct _TEB *)__readgsqword(0x30))
#else
#define NtCurrentTeb() ((struct _TEB *)__readfsdword(0x18))
#endif

        typedef struct _TEB {
            PVOID Reserved1[12];
            PPEB ProcessEnvironmentBlock;
            // Add more fields as needed
        } TEB, *PTEB;

        typedef NTSTATUS(NTAPI* fnNtQueryVirtualMemory)(
            HANDLE ProcessHandle,
            PVOID BaseAddress,
            int MemoryInformationClass,
            PVOID MemoryInformation,
            SIZE_T MemoryInformationLength,
            PSIZE_T ReturnLength
        );

        typedef NTSTATUS(NTAPI* fnNtQueryInformationThread)(
            HANDLE ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID ThreadInformation,
            ULONG ThreadInformationLength,
            PULONG ReturnLength
        );

        std::wstring DevicePathToDrivePath(const std::wstring& devicePath);
        std::vector<std::wstring> GetMappedModulePaths();
        std::vector<uintptr_t> GetSuspiciousRegions();
        void ScanVAD();

        void ScanThreads();


        void SetUpWhitelist();
        bool IsModuleWhitelisted(const std::wstring& name);
        void ScanLoadedModules();

        void PEBScanner();
        void FullScanner();
    } // Scanner

    namespace Level2 {

        class EncryptedPlayer {
        private:
            int _health;
            const char* _name;
            static constexpr unsigned int KEY = 0xDEADBEEF;

            static int Encrypt(int val) { return val ^ KEY; }
            static int Decrypt(int val) { return val ^ KEY; }

        public:
            EncryptedPlayer(const char* name, const int health)
                : _health(Encrypt(health)), _name(name) {}

            [[nodiscard]] const char* GetName() const;

            [[nodiscard]] int GetHealth() const;
            void SetHealth(int health);

            void AppyHeal();
            void ApplyDamage();
        };

        void Start();
    } // Level2

    namespace Level3 {
        class EncryptedPlayer {
        private:
            int _health;
            const char* _name;
            unsigned char _key[16]{};
            unsigned char _iv[16]{};

            void InitCrypto();
            int Encrypt(int val) const;
            int Decrypt(int val) const;

        public:
            EncryptedPlayer(const char* name, int health);

            [[nodiscard]] const char* GetName() const;
            [[nodiscard]] int GetHealth() const;
            void SetHealth(int health);
            void AppyHeal();
            void ApplyDamage();
        };

        void Start();
    } // Level3
} // Protection

#endif //SOFT_SEC_FINAL_PROTECTION_H