#pragma once
#include <fstream>
#include <filesystem>
#include "../Memory/Memory.hpp"
#include "../Defs.hpp"

extern std::string g_DllPath;
extern uintptr_t g_Shared, g_DllSz, g_DllBase;

uintptr_t GetRva(uintptr_t rva, PIMAGE_NT_HEADERS nt, uint8_t* raw);
BOOL Reloc(uintptr_t rem, PVOID loc, PIMAGE_NT_HEADERS nt);

namespace mapr {
    void Map(std::string);
}

SIZE_T DllSz(const std::filesystem::path& p);
