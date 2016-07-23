#pragma once

#include <Windows.h>
#include <duktape.h>

duk_ret_t sizeOfPtr(duk_context* ctx);
duk_ret_t addressOf(duk_context *ctx);
duk_ret_t charCodeAt(duk_context *ctx);

duk_ret_t writeMemory(duk_context *ctx);
duk_ret_t readMemory(duk_context *ctx);
duk_ret_t readString(duk_context *ctx);

// Implementations

template <typename F>
F CreateHook(void* orig, F dest, bool createCodecave=false, int len=5)
{
    DWORD codecave = NULL;

    if (createCodecave)
    {
        codecave = (DWORD)VirtualAlloc(NULL, 5 + len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!codecave)
        {
            return NULL;
        }

        memcpy((void*)codecave, (void*)orig, len);

        *(BYTE*)(codecave + len) = 0xE9;
        *(DWORD*)(codecave + len + 1) = ((DWORD)orig + len - (codecave + len)) - 5;
    }

    // Unprotect address
    DWORD oldProtect;
    VirtualProtect((LPVOID)orig, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // JMP dest
    *(BYTE*)(orig) = 0xE9;
    *(DWORD*)((DWORD)orig + 1) = ((DWORD)dest - (DWORD)orig) - 5;

	for (int i = 5; i < len; ++i)
	{
		*(BYTE*)(orig + i) = 0x90;
	}

    VirtualProtect((LPVOID)orig, 5, oldProtect, &oldProtect);

    return (F)codecave;
}
