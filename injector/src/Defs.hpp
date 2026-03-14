#pragma once
#include <Windows.h>

using fLdrEx = HMODULE(__stdcall*)(LPCSTR, HANDLE, DWORD);
using fLdr = HMODULE(__stdcall*)(LPCSTR);
using fProc = FARPROC(__stdcall*)(HMODULE, LPCSTR);
using fTab = BOOLEAN(__cdecl*)(PRUNTIME_FUNCTION, DWORD, DWORD64);

#define SH(f, v) Write<decltype(Shared::f)>(g_Shared + offsetof(Shared, f), v)

enum class State { Load, Wait, Inject, Done };

struct Shared {
    fLdrEx LdrEx;
    fLdr Ldr;
    fProc Proc;
    fTab AddTab;
    uintptr_t dllSt, dllEd, dllEp, ExcVA, ExcSz, ImpVA, ImpSz, TlsVA, TlsSz;
    State Status;
};