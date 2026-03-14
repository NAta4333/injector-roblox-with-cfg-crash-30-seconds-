#include <Windows.h>
#include <thread>
#include <stdexcept>

using print_t = void(__cdecl*)(unsigned int, const char*, ...);

void printy()
{
    auto base = (uintptr_t)GetModuleHandleW(NULL);
    auto print = (print_t)(base + 0x1C7BFE0);

    int prefix = 0;
    int sec = 0;
    while (true)
    {
        print(prefix, "Vitual is injected for: %ds", sec++);
        prefix = (prefix + 1) % 4;
        Sleep(1000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        std::thread(printy).detach();
    }
    return TRUE;
}