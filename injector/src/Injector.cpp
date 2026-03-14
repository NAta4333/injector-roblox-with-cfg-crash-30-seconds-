#include <iostream>
#include <vector>
#include <algorithm>
#include <filesystem>
#include "Memory/Memory.hpp"
#include "Mapper/Mapper.hpp"
#include "CFG/CFG.hpp"
#include "Defs.hpp"
#include "PoolParty/PoolParty.hpp"

uintptr_t Hook(uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    auto s = (Shared*)0x100000000;
    if (!s) return 0;

    if (s->Status == State::Load) {
        s->Status = State::Wait;
        char m[] = { 'm', 's', 'h', 't', 'm', 'l', '.', 'd', 'l', 'l', '\0' };
        if (s->LdrEx) s->LdrEx(m, NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if (s->Status == State::Inject) {
        auto d = s->dllSt;
        if (!d) return 0;

        if (s->ExcSz && s->AddTab)
            s->AddTab((PRUNTIME_FUNCTION)((BYTE*)d + s->ExcVA), s->ExcSz / sizeof(RUNTIME_FUNCTION), (DWORD64)d);

        auto i = (PIMAGE_IMPORT_DESCRIPTOR)(d + s->ImpVA);
        auto ie = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)i + s->ImpSz);
        while (i < ie && i->Name) {
            HMODULE l = (s->Ldr) ? s->Ldr((char*)(d + i->Name)) : NULL;
            if (!l) { ++i; continue; }
            uintptr_t* t = (uintptr_t*)(d + (i->OriginalFirstThunk ? i->OriginalFirstThunk : i->FirstThunk));
            FARPROC* f = (FARPROC*)(d + i->FirstThunk);
            for (; *t; ++t, ++f) {
                if (!s->Proc) break;
                if (IMAGE_SNAP_BY_ORDINAL(*t)) *f = s->Proc(l, MAKEINTRESOURCEA(IMAGE_ORDINAL(*t)));
                else *f = s->Proc(l, ((IMAGE_IMPORT_BY_NAME*)(d + *t))->Name);
            }
            ++i;
        }

        if (s->TlsVA && s->TlsSz) {
            auto t = (IMAGE_TLS_DIRECTORY64*)(d + s->TlsVA);
            ULONGLONG rv = t->AddressOfCallBacks;
            if (rv) {
                uintptr_t c = (uintptr_t)rv;
                if (c < d || c >= s->dllEd) c = d + (uintptr_t)rv;
                PIMAGE_TLS_CALLBACK* cl = (PIMAGE_TLS_CALLBACK*)c;
                for (size_t k = 0;; ++k) {
                    if (!cl[k]) break;
                    cl[k]((PVOID)d, DLL_PROCESS_ATTACH, nullptr);
                }
            }
        }
        if (s->dllEp) {
            ((BOOL(__stdcall*)(HMODULE, DWORD, LPVOID))(s->dllEp))((HMODULE)d, DLL_PROCESS_ATTACH, nullptr);
        }
        s->Status = State::Done;
    }
    return 0;
}

HANDLE g_hProc = nullptr;
DWORD g_Pid = 0;

bool Inject(DWORD pid) {
    g_Pid = pid;
    std::vector<MODULEENTRY32> mods;
    GetMods(g_Pid, { "KERNELBASE.dll", "KERNEL32.dll", "ntdll.dll" }, mods);
    if (mods.size() < 3 || !mods[0].modBaseAddr || !mods[1].modBaseAddr) return false;

    uintptr_t kbBase = (uintptr_t)mods[0].modBaseAddr;
    uintptr_t k3Base = (uintptr_t)mods[1].modBaseAddr;
    uintptr_t ntBase = (uintptr_t)mods[2].modBaseAddr;

    g_Shared = Alloc(sizeof(Shared), PAGE_READWRITE);
    if (!g_Shared) return false;

    Shared loc = {};
    loc.LdrEx = (fLdrEx)GetProc(kbBase, "LoadLibraryExA");
    loc.Ldr = (fLdr)GetProc(k3Base, "LoadLibraryA");
    loc.Proc = (fProc)GetProc(k3Base, "GetProcAddress");
    loc.AddTab = (fTab)GetProc(ntBase, "RtlAddFunctionTable");
    loc.Status = State::Load;
    Write(g_Shared, &loc, sizeof(Shared));

    std::vector<BYTE> sc = ExtSc((uintptr_t)Hook);
    if (sc.empty()) {
        Prot(g_Shared, sizeof(Shared), PAGE_NOACCESS);
        return false;
    }
    RepSc(sc, 0x100000000ULL, g_Shared);

    try {
        RemoteTpDirectInsertion poolParty(g_Pid, sc.data(), sc.size());
        poolParty.Inject();
        Sleep(100);
        poolParty.Cleanup();
    } catch (...) { 
        Prot(g_Shared, sizeof(Shared), PAGE_NOACCESS);
        return false; 
    }

    MODULEENTRY32 msme = {};
    int wait_count = 0;
    while (!msme.modBaseAddr && wait_count < 40) { 
        msme = GetMod(g_Pid, "mshtml.dll"); 
        Sleep(250);
        wait_count++;
    }

    if (!msme.modBaseAddr) {
        Prot(g_Shared, sizeof(Shared), PAGE_NOACCESS);
        return false;
    }

    Prot((uintptr_t)msme.modBaseAddr, msme.modBaseSize, PAGE_EXECUTE_READWRITE);
    std::vector<BYTE> z(msme.modBaseSize - 0x1000, 0);
    Write((uintptr_t)msme.modBaseAddr + 0x1000, z.data(), z.size());

    g_DllBase = (uintptr_t)msme.modBaseAddr;
    g_DllSz = DllSz(g_DllPath);
    SH(dllSt, g_DllBase);
    SH(dllEd, g_DllBase + g_DllSz);
    mapr::Map(g_DllPath);

    MODULEENTRY32 robloxDll = GetMod(g_Pid, "RobloxPlayerBeta.dll");
    if (robloxDll.modBaseAddr) {
        uintptr_t robloxBase = (uintptr_t)robloxDll.modBaseAddr;
        std::cout << "robloxplayerleta.dll base: 0x" << std::hex << robloxBase << std::dec << std::endl;
        try {
            if (ControlFlowGuard::DisableCFG(g_hProc, robloxBase, g_DllBase, g_DllSz)) {
                std::cout << "cfg disabled" << std::endl;
            } else {
                std::cout << "cfg failed" << std::endl;
            }
        } catch (...) {
            std::cout << "cfg disable exception" << std::endl;
        }
    } else {
        std::cout << "robloxplayerbeta.dll not found" << std::endl;
    }

    SH(Status, State::Inject);
    try {
        if (!sc.empty()) {
            RemoteTpDirectInsertion poolParty(g_Pid, sc.data(), sc.size());
            poolParty.Inject();

            DWORD waitMs = 0;
            const DWORD MAX_WAIT = 30000;
            while (Read<State>(g_Shared + offsetof(Shared, Status)) != State::Done && waitMs < MAX_WAIT) {
                Sleep(10);
                waitMs += 10;
            }

            poolParty.Cleanup();

            if (waitMs >= MAX_WAIT) {
                std::cout << "Injection timeout" << std::endl;
                Prot(g_Shared, sizeof(Shared), PAGE_NOACCESS);
                return false;
            }
        }
    } catch (...) {
        Prot(g_Shared, sizeof(Shared), PAGE_NOACCESS);
        return false;
    }
    return true;
}

int main() {
    g_DllPath = (std::filesystem::current_path() / "module.dll").string();
    if (!std::filesystem::exists(g_DllPath)) {
        std::cout << "module.dll not found" << std::endl;
        system("pause");
        return 0;
    }

    DWORD pid = 0;
    while (pid == 0) {
        pid = GetPid("RobloxPlayerBeta.exe");
        if (!pid) Sleep(500);
    }

    g_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!g_hProc) {
        std::cout << "Failed to open process" << std::endl;
        system("pause");
        return 0;
    }

    std::cout << "inj: " << pid << std::endl;
    if (Inject(pid)) std::cout << "ok" << std::endl;
    else std::cout << "injection failed" << std::endl;

    CloseHandle(g_hProc);
    system("pause");
    return 0;
}