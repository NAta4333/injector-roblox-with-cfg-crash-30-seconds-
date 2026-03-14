#include "Mapper.hpp"

std::string g_DllPath;
uintptr_t g_Shared, g_DllSz, g_DllBase;

uintptr_t GetRva(uintptr_t rva, PIMAGE_NT_HEADERS nt, uint8_t* raw) {
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
    for (PIMAGE_SECTION_HEADER s = first; s < first + nt->FileHeader.NumberOfSections; s++)
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + s->Misc.VirtualSize)
            return (uintptr_t)raw + s->PointerToRawData + (rva - s->VirtualAddress);
    return 0;
}

BOOL Reloc(uintptr_t rem, PVOID loc, PIMAGE_NT_HEADERS nt) {
    struct RelocEnt {
        ULONG Page, Size;
        struct { WORD Off : 12, Type : 4; } Item[1];
    };
    uintptr_t delta = rem - nt->OptionalHeader.ImageBase;
    if (!delta) return 1;
    if (!(nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return 0;
    RelocEnt* ent = (RelocEnt*)GetRva(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt, (uint8_t*)loc);
    uintptr_t end = (uintptr_t)ent + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!ent) return 1;
    while ((uintptr_t)ent < end && ent->Size && ent->Size >= 8) {
        DWORD count = (ent->Size - 8) >> 1;
        for (DWORD i = 0; i < count; i++) {
            if (ent->Item[i].Type == 3 || ent->Item[i].Type == 10) {
                uintptr_t va = GetRva(ent->Page, nt, (uint8_t*)loc);
                if (!va) va = (uintptr_t)loc;
                *(uintptr_t*)(va + (ent->Item[i].Off % 4096)) += delta;
            }
        }
        ent = (RelocEnt*)((LPBYTE)ent + ent->Size);
    }
    return 1;
}

SIZE_T DllSz(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) return 0;
    IMAGE_DOS_HEADER d = { 0 };
    f.read((char*)&d, sizeof(d));
    if (d.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS nt = { 0 };
    f.seekg(d.e_lfanew);
    f.read((char*)&nt, sizeof(nt));
    return (nt.Signature != IMAGE_NT_SIGNATURE) ? 0 : nt.OptionalHeader.SizeOfImage;
}

void mapr::Map(std::string path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return;

    std::streampos szpos = f.tellg();
    size_t sz = (size_t)szpos;
    PBYTE buf = (PBYTE)malloc(sz);
    if (!buf) {
        f.close();
        return;
    }

    f.seekg(0);
    f.read((char*)buf, sz);
    f.close();

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_lfanew < 0 || dos->e_lfanew > (int)(sz - sizeof(IMAGE_NT_HEADERS))) {
        free(buf);
        return;
    }

    PIMAGE_NT_HEADERS nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        free(buf);
        return;
    }

    auto entry = g_DllBase + nt->OptionalHeader.AddressOfEntryPoint;
    auto tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    auto imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    SH(TlsVA, tls.VirtualAddress);
    SH(TlsSz, tls.Size);
    SH(ImpVA, imp.VirtualAddress);
    SH(ImpSz, imp.Size);
    SH(dllEp, entry);
    if (!Reloc(g_DllBase, buf, nt)) {
        free(buf);
        return;
    }
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0 || (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) continue;
        Write(g_DllBase + sec->VirtualAddress, buf + sec->PointerToRawData, sec->SizeOfRawData);
    }
    auto ex = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ex.Size) {
        SH(ExcVA, ex.VirtualAddress);
        SH(ExcSz, ex.Size);
    }
    free(buf);
}