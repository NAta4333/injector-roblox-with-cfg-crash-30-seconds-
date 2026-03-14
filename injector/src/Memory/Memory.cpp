#include "Memory.hpp"

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

static NtReadVirtualMemory_t fR = nullptr;
static NtWriteVirtualMemory_t fW = nullptr;
static NtProtectVirtualMemory_t fP = nullptr;
static NtAllocateVirtualMemory_t fA = nullptr;

NtReadVirtualMemory_t g_NtRead = nullptr;
NtWriteVirtualMemory_t g_NtWrite = nullptr;

static void Init() {
    if (fR) return;
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (h) {
        fR = (NtReadVirtualMemory_t)GetProcAddress(h, "NtReadVirtualMemory");
        fW = (NtWriteVirtualMemory_t)GetProcAddress(h, "NtWriteVirtualMemory");
        fP = (NtProtectVirtualMemory_t)GetProcAddress(h, "NtProtectVirtualMemory");
        fA = (NtAllocateVirtualMemory_t)GetProcAddress(h, "NtAllocateVirtualMemory");
        g_NtRead = fR;
        g_NtWrite = fW;
    }
}

bool Read(uintptr_t adr, void* buf, size_t sz) {
    Init();
    if (!fR || !g_hProc) return false;
    ULONG b;
    return fR(g_hProc, (PVOID)adr, buf, (ULONG)sz, &b) == 0;
}

bool Write(uintptr_t adr, const void* buf, size_t sz) {
    Init();
    if (!fW || !g_hProc) return false;
    ULONG b;
    return fW(g_hProc, (PVOID)adr, (PVOID)buf, (ULONG)sz, &b) == 0;
}

bool Prot(uintptr_t adr, SIZE_T sz, DWORD nPr) {
    Init();
    if (!fP || !g_hProc) return false;
    PVOID b = (PVOID)adr;
    ULONG s = (ULONG)sz;
    ULONG o;
    return fP(g_hProc, &b, &s, nPr, &o) == 0;
}

uintptr_t Alloc(SIZE_T sz, DWORD nPr) {
    Init();
    if (!fA || !g_hProc) return 0;
    PVOID b = nullptr;
    SIZE_T s = sz;
    return fA(g_hProc, &b, 0, &s, MEM_COMMIT | MEM_RESERVE, nPr) == 0 ? (uintptr_t)b : 0;
}

DWORD GetPid(const char* n) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ok = Process32First(s, &pe); ok; ok = Process32Next(s, &pe)) {
        if (!_stricmp(pe.szExeFile, n)) { CloseHandle(s); return pe.th32ProcessID; }
    }
    CloseHandle(s);
    return 0;
}

std::vector<DWORD> GetPids(const char* n) {
    std::vector<DWORD> pids;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ok = Process32First(s, &pe); ok; ok = Process32Next(s, &pe)) {
        if (!_stricmp(pe.szExeFile, n)) pids.push_back(pe.th32ProcessID);
    }
    CloseHandle(s);
    return pids;
}

MODULEENTRY32 GetMod(DWORD p, const char* m) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (s == INVALID_HANDLE_VALUE) return {};
    MODULEENTRY32 me = { sizeof(me) };
    for (BOOL ok = Module32First(s, &me); ok; ok = Module32Next(s, &me)) {
        if (!_stricmp(me.szModule, m)) { CloseHandle(s); return me; }
    }
    CloseHandle(s);
    return {};
}

void GetMods(DWORD p, std::vector<const char*> names, std::vector<MODULEENTRY32>& results) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (s == INVALID_HANDLE_VALUE) return;
    results.resize(names.size(), {});
    MODULEENTRY32 me = { sizeof(me) };
    for (BOOL ok = Module32First(s, &me); ok; ok = Module32Next(s, &me)) {
        for (size_t i = 0; i < names.size(); ++i) {
            if (!_stricmp(me.szModule, names[i])) { results[i] = me; break; }
        }
    }
    CloseHandle(s);
}

uintptr_t GetProc(uintptr_t b, const char* n) {
    auto d = Read<IMAGE_DOS_HEADER>(b);
    auto nt = Read<IMAGE_NT_HEADERS>(b + d.e_lfanew);
    auto e = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!e.VirtualAddress || !e.Size) return 0;
    auto ex = Read<IMAGE_EXPORT_DIRECTORY>(b + e.VirtualAddress);
    std::vector<DWORD> v1(ex.NumberOfNames);
    std::vector<WORD> v2(ex.NumberOfNames);
    std::vector<DWORD> v3(ex.NumberOfFunctions);
    if (!Read(b + ex.AddressOfNames, v1.data(), 4 * v1.size()) || !Read(b + ex.AddressOfNameOrdinals, v2.data(), 2 * v2.size()) || !Read(b + ex.AddressOfFunctions, v3.data(), 4 * v3.size()))
        return 0;
    for (size_t i = 0; i < v1.size(); ++i) {
        char buf[128]{ 0 };
        if (!Read(b + v1[i], buf, sizeof(buf))) continue;
        if (!strcmp(buf, n)) {
            WORD o = v2[i];
            if (o >= v3.size()) return 0;
            return b + v3[o];
        }
    }
    return 0;
}

std::vector<BYTE> ExtSc(uintptr_t f) {
    MEMORY_BASIC_INFORMATION m;
    VirtualQuery((void*)f, &m, sizeof(m));
    size_t s = m.RegionSize;
    std::vector<BYTE> sc;
    for (size_t i = 0; i < s; ++i) {
        BYTE v = *(BYTE*)(f + i);
        sc.push_back(v);
        if (v == 0xCC && i + 2 < s && *(BYTE*)(f + i + 1) == 0xCC && *(BYTE*)(f + i + 2) == 0xCC) break;
    }
    return sc;
}

void RepSc(std::vector<BYTE>& d, uint64_t s, uint64_t r) {
    if (d.size() < 10) return;
    for (size_t i = 0; i <= d.size() - 10; ++i) {
        if ((d[i] == 0x48 || d[i] == 0x49) && d[i + 1] >= 0xB8 && d[i + 1] <= 0xBF) {
            uint64_t m = *(uint64_t*)(&d[i + 2]), o = *(uint32_t*)(&d[i + 2]);
            if (m - o == s) {
                uintptr_t nr = (uintptr_t)(r + o);
                memcpy(&d[i + 2], &nr, 8);
            }
        }
        uint64_t q = *(uint64_t*)(&d[i + 1]), o2 = *(uint32_t*)(&d[i + 1]);
        if ((d[i] == 0xA1 || d[i] == 0xA2 || d[i] == 0xA3) && q - o2 == s) {
            uintptr_t nr2 = (uintptr_t)(r + o2);
            memcpy(&d[i + 1], &nr2, 8);
        }
    }
}