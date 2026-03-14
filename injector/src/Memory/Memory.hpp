#pragma once
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);

extern HANDLE g_hProc;
extern DWORD g_Pid;
extern NtReadVirtualMemory_t g_NtRead;
extern NtWriteVirtualMemory_t g_NtWrite;

bool Read(uintptr_t adr, void* buf, size_t sz);
bool Write(uintptr_t adr, const void* buf, size_t sz);

template<typename T>
T Read(uintptr_t adr) {
    T val{};
    Read(adr, &val, sizeof(T));
    return val;
}

template<typename T>
bool Write(uintptr_t adr, const T& val) {
    return Write(adr, (const void*)&val, sizeof(T));
}

bool Prot(uintptr_t adr, SIZE_T sz, DWORD nPr);
uintptr_t Alloc(SIZE_T sz, DWORD nPr);

DWORD GetPid(const char* n);
std::vector<DWORD> GetPids(const char* n);
MODULEENTRY32 GetMod(DWORD p, const char* m);
void GetMods(DWORD p, std::vector<const char*> names, std::vector<MODULEENTRY32>& results);
uintptr_t GetProc(uintptr_t b, const char* n);

std::vector<BYTE> ExtSc(uintptr_t f);
void RepSc(std::vector<BYTE>& d, uint64_t s, uint64_t r);

uintptr_t GetHbk(uintptr_t j);
uintptr_t GetVtableFunc(uintptr_t obj, size_t idx);