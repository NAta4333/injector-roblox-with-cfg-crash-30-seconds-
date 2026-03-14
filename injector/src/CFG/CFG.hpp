#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include "../Memory/Memory.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class ControlFlowGuard {
private:
 
    static const uintptr_t BitmapPointerOffset = 0x1714960;

    enum CFGOffsets {
        ByteShift = 15,
        PageShift = 12,
        BitMask = 7,
        PageSize = 0x1000,
        PageMask = 0xFFF
    };

public:
    static bool DisableCFG(
        HANDLE ProcessHandle,
        uintptr_t RobloxPlayerBetaBase,
        uintptr_t TargetBase,
        size_t RegionSize
    ) {
        if (!RobloxPlayerBetaBase || !TargetBase || !RegionSize || TargetBase > 0x7FFFFFFFFFFFULL) {
            std::cout << "invalid parameters" << std::endl;
            return false;
        }

      
        Read<BYTE>(TargetBase);

        if (!g_NtRead || !g_NtWrite) {
            std::cout << "not initialized" << std::endl;
            return false;
        }

        uintptr_t BitmapPointerAddr = RobloxPlayerBetaBase + BitmapPointerOffset;
        std::cout << "bitmap pointer = 0x" << std::hex << BitmapPointerAddr << std::dec << std::endl;

        uintptr_t BitmapPtr = 0;
        ULONG bytes = 0;

   
        NTSTATUS status = g_NtRead(ProcessHandle,
            (PVOID)BitmapPointerAddr,
            &BitmapPtr,
            sizeof(BitmapPtr),
            &bytes);

        std::cout << "bitmap pointer status = 0x" << std::hex << status << std::dec;
        std::cout << " BitmapPtr = 0x" << std::hex << BitmapPtr << std::dec << std::endl;

        if (!NT_SUCCESS(status) || !BitmapPtr) {
            std::cout << "fl to read bitmap pointer" << std::endl;
            return false;
        }

        uintptr_t Start = TargetBase & ~PageMask;
        uintptr_t End = (TargetBase + RegionSize + PageMask) & ~PageMask;
        std::cout << "disabl cfg range 0x" << std::hex << Start << " - 0x" << End << std::dec << std::endl;

        int cleared = 0;
        for (uintptr_t CurrentAddr = Start; CurrentAddr < End; CurrentAddr += PageSize) {
         
            uintptr_t ByteOffset = (CurrentAddr >> ByteShift);
            uintptr_t BitOffset = (CurrentAddr >> PageShift) & BitMask;

            uintptr_t RemoteByteAddr = BitmapPtr + ByteOffset;

         
            uintptr_t PageAlignedAddr = RemoteByteAddr & ~0xFFF;
            VirtualAllocEx(ProcessHandle, (LPVOID)PageAlignedAddr, 0x1000, MEM_COMMIT, PAGE_READWRITE);

            uint8_t value = 0;

            status = g_NtRead(ProcessHandle,
                (PVOID)RemoteByteAddr,
                &value,
                sizeof(value),
                &bytes);

            if (!NT_SUCCESS(status)) {
                std::cout << "failed read byte at 0x" << std::hex << RemoteByteAddr 
                         << " status = 0x" << status << std::dec << std::endl;
                return false;
            }

            value |= (uint8_t)(1 << BitOffset);

            status = g_NtWrite(ProcessHandle,
                (PVOID)RemoteByteAddr,
                &value,
                sizeof(value),
                &bytes);

            if (!NT_SUCCESS(status)) {
                std::cout << "failed write byte at 0x" << std::hex << RemoteByteAddr 
                         << " status = 0x" << status << std::dec << std::endl;
                return false;
            }

            cleared++;
        }

        std::cout << "Disabled cfg for " << cleared << " pages" << std::endl;
        return true;
    }
};
