#include "redirect.hpp"
#include "helpers.hpp"

#include <Windows.h>
#include <Psapi.h>

#ifdef BUILD_64

typedef DWORD_PTR QWORD;
extern HINSTANCE dllhandle;

DWORD_PTR lastMemory = NULL;
size_t remainingSize = 0x00;

void* GetNearMemory(LPVOID address, size_t size)
{
	DWORD_PTR mem = NULL;
	
	if (size < remainingSize && lastMemory != NULL)
	{
		mem = (DWORD_PTR)lastMemory;
		lastMemory += size;
		remainingSize -= size;
	}
	else
	{
		if (address == NULL)
		{
			MODULEINFO modInfo;
			GetModuleInformation(GetCurrentProcess(), dllhandle, &modInfo, sizeof(MODULEINFO));
			address = (LPVOID)((QWORD)modInfo.EntryPoint + modInfo.SizeOfImage);
		}

		for (int i = 0; i < 20; ++i)
		{
			address = (LPVOID)((QWORD)address + i * 0x10000);
			MEMORY_BASIC_INFORMATION mi = { 0 };
			VirtualQuery(address, &mi, sizeof(mi));

			if (mi.State == MEM_FREE)
			{
				mem = (DWORD_PTR)VirtualAlloc(address, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (mem)
				{
					lastMemory = mem + size;
					remainingSize = 0x10000 - size;
					break;
				}
			}
		}
	}

	return (LPVOID)mem;
}

void* CreateJSRedirect()
{
	DWORD_PTR mem = (DWORD_PTR)GetNearMemory(NULL, 245);

	DWORD_PTR mem_start = mem;

	// push RDX
	*(BYTE*)(mem + 0) = 0x52;
	// push RCX
	*(BYTE*)(mem + 1) = 0x51;

	mem += 2;
	// mov rdx, qword ptr [rsp + 16]
	*(BYTE*)(mem + 0) = 0x48;
	*(BYTE*)(mem + 1) = 0x8B;
	*(BYTE*)(mem + 2) = 0x54;
	*(BYTE*)(mem + 3) = 0x24;
	*(BYTE*)(mem + 4) = 0x10;

	mem += 5;
	// movabs rcx, 928182171271
	*(WORD*)(mem + 0) = 0xB948;
	*(QWORD*)(mem + 2) = (QWORD)ctx;

	mem += 10;
	// sub rsp, 28
	*(BYTE*)(mem + 0) = 0x48;
	*(BYTE*)(mem + 1) = 0x83;
	*(BYTE*)(mem + 2) = 0xEC;
	*(BYTE*)(mem + 3) = 0x28;
	// duk_get_global_string(ctx, currentName);
	*(BYTE*)(mem + 4) = 0xE8;
	*(DWORD*)(mem + 5) = ((QWORD)&duk_get_global_string - (mem + 4)) - 5;
	// add rsp, 28
	*(BYTE*)(mem + 9) = 0x48;
	*(BYTE*)(mem + 10) = 0x83;
	*(BYTE*)(mem + 11) = 0xC4;
	*(BYTE*)(mem + 12) = 0x28;

	mem += 13;
	// mov rbx, qword ptr ss : [rsp + 24] = 4 * 3 = 12 .... 8 * 3 = 24
	*(BYTE*)(mem + 0) = 0x48;
	*(BYTE*)(mem + 1) = 0x8B;
	*(BYTE*)(mem + 2) = 0x5C;
	*(BYTE*)(mem + 3) = 0x24;
	*(BYTE*)(mem + 4) = 0x18;

	mem += 5;
	// mov EDI, EBX
	*(WORD*)(mem + 0) = 0xDF89;

	mem += 2;
	// if (num_args > 0) {
		// test EDI, EDI
		*(WORD*)(mem + 0) = 0xFF85;

		// jmp fuera if
		*(BYTE*)(mem + 2) = 0x74;
		*(BYTE*)(mem + 3) = 0x1C;  // Distancia hasta call_duktape - 2 (0-128 ----> / 128 - 255 <-------)

		// pop RDX
		*(BYTE*)(mem + 4) = 0x5A;

		// movabs rcx, 928182171271
		*(WORD*)(mem + 5) = 0xB948;
		*(QWORD*)(mem + 7) = (QWORD)ctx;

		// sub rsp, 28
		*(BYTE*)(mem + 15) = 0x48;
		*(BYTE*)(mem + 16) = 0x83;
		*(BYTE*)(mem + 17) = 0xEC;
		*(BYTE*)(mem + 18) = 0x28;
		// duk_push_int(ctx, argVal);
		*(BYTE*)(mem + 19) = 0xE8;
		*(DWORD*)(mem + 20) = ((QWORD)&duk_push_pointer - (mem + 19)) - 5;
		// add rsp, 28
		*(BYTE*)(mem + 24) = 0x48;
		*(BYTE*)(mem + 25) = 0x83;
		*(BYTE*)(mem + 26) = 0xC4;
		*(BYTE*)(mem + 27) = 0x28;

		// dec EDI
		*(WORD*)(mem + 28) = 0xCFFF;

		*(BYTE*)(mem + 30) = 0x74;
		*(BYTE*)(mem + 31) = 0x01;
	// }

	*(BYTE*)(mem + 32) = 0x59;	

	mem += 33;
	// if (num_args > 0) {
		// test EDI, EDI
		*(WORD*)(mem + 0) = 0xFF85;

		// jmp fuera if
		*(BYTE*)(mem + 2) = 0x74;
		*(BYTE*)(mem + 3) = 0x1C;  // Distancia hasta call_duktape - 2 (0-128 ----> / 128 - 255 <-------)

		// pop RDX
		*(BYTE*)(mem + 4) = 0x5A;

		// movabs rcx, 928182171271
		*(WORD*)(mem + 5) = 0xB948;
		*(QWORD*)(mem + 7) = (QWORD)ctx;

		// sub rsp, 28
		*(BYTE*)(mem + 15) = 0x48;
		*(BYTE*)(mem + 16) = 0x83;
		*(BYTE*)(mem + 17) = 0xEC;
		*(BYTE*)(mem + 18) = 0x28;
		// duk_push_int(ctx, argVal);
		*(BYTE*)(mem + 19) = 0xE8;
		*(DWORD*)(mem + 20) = ((QWORD)&duk_push_pointer - (mem + 19)) - 5;
		// add rsp, 28
		*(BYTE*)(mem + 24) = 0x48;
		*(BYTE*)(mem + 25) = 0x83;
		*(BYTE*)(mem + 26) = 0xC4;
		*(BYTE*)(mem + 27) = 0x28;

		// dec EDI
		*(WORD*)(mem + 28) = 0xCFFF;

		*(BYTE*)(mem + 30) = 0x74;
		*(BYTE*)(mem + 31) = 0x01;
	// }

	*(BYTE*)(mem + 32) = 0x59;

	mem += 33;
	// if (num_args > 0) {
		// test EDI, EDI
		*(WORD*)(mem + 0) = 0xFF85;

		// jmp fuera if
		*(BYTE*)(mem + 2) = 0x74;
		*(BYTE*)(mem + 3) = 0x1C;  // Distancia hasta call_duktape - 2 (0-128 ----> / 128 - 255 <-------)

		// MOV RDX, R8
		*(BYTE*)(mem + 4) = 0x4C;
		*(BYTE*)(mem + 5) = 0x89;
		*(BYTE*)(mem + 6) = 0xC2;
		
		// movabs rcx, 928182171271
		*(WORD*)(mem + 7) = 0xB948;
		*(QWORD*)(mem + 9) = (QWORD)ctx;

		// sub rsp, 28
		*(BYTE*)(mem + 17) = 0x48;
		*(BYTE*)(mem + 18) = 0x83;
		*(BYTE*)(mem + 19) = 0xEC;
		*(BYTE*)(mem + 20) = 0x28;
		// duk_push_int(ctx, argVal);
		*(BYTE*)(mem + 21) = 0xE8;
		*(DWORD*)(mem + 22) = ((QWORD)&duk_push_pointer - (mem + 21)) - 5;
		// add rsp, 28
		*(BYTE*)(mem + 26) = 0x48;
		*(BYTE*)(mem + 27) = 0x83;
		*(BYTE*)(mem + 28) = 0xC4;
		*(BYTE*)(mem + 29) = 0x28;

		// dec EDI
		*(WORD*)(mem + 30) = 0xCFFF;
	// }

	mem += 32;
	// if (num_args > 0) {
		// test EDI, EDI
		*(WORD*)(mem + 0) = 0xFF85;

		// jmp fuera if
		*(BYTE*)(mem + 2) = 0x74;
		*(BYTE*)(mem + 3) = 0x1C;  // Distancia hasta call_duktape - 2 (0-128 ----> / 128 - 255 <-------)

		// MOV RDX, R8
		*(BYTE*)(mem + 4) = 0x4C;
		*(BYTE*)(mem + 5) = 0x89;
		*(BYTE*)(mem + 6) = 0xCA;

		// movabs rcx, 928182171271
		*(WORD*)(mem + 7) = 0xB948;
		*(QWORD*)(mem + 9) = (QWORD)ctx;

		// sub rsp, 28
		*(BYTE*)(mem + 17) = 0x48;
		*(BYTE*)(mem + 18) = 0x83;
		*(BYTE*)(mem + 19) = 0xEC;
		*(BYTE*)(mem + 20) = 0x28;
		// duk_push_int(ctx, argVal);
		*(BYTE*)(mem + 21) = 0xE8;
		*(DWORD*)(mem + 22) = ((QWORD)&duk_push_pointer - (mem + 21)) - 5;
		// add rsp, 28
		*(BYTE*)(mem + 26) = 0x48;
		*(BYTE*)(mem + 27) = 0x83;
		*(BYTE*)(mem + 28) = 0xC4;
		*(BYTE*)(mem + 29) = 0x28;

		// dec EDI
		*(WORD*)(mem + 30) = 0xCFFF;
	// }

	mem += 32;
	// for each argument
loop_args:
	// test EDI, EDI
	*(WORD*)(mem + 0) = 0xFF85;
	// je call_duktape
	*(BYTE*)(mem + 2) = 0x74;
	*(BYTE*)(mem + 3) = 0x2A;  // Distancia hasta call_duktape - 2 (0-128 ----> / 128 - 255 <-------)

	// Cada parametro = 8 bytes ... 1, 2, 3 * 8 = 8, 16, 24 ...
	// mov RAX, 8
	*(BYTE*)(mem + 4) = 0x48;
	*(BYTE*)(mem + 5) = 0xC7;
	*(BYTE*)(mem + 6) = 0xC0;
	*(DWORD*)(mem + 7) = 8;

	// imul EAX, EDI
	*(BYTE*)(mem + 11) = 0x0F;
	*(BYTE*)(mem + 12) = 0xAF;
	*(BYTE*)(mem + 13) = 0xC7;

	// mov rcx, qword ptr [rbp + rax + 0x10]
	*(BYTE*)(mem + 14) = 0x48;
	*(BYTE*)(mem + 15) = 0x8B;
	*(BYTE*)(mem + 16) = 0x4C;
	*(BYTE*)(mem + 17) = 0x05;
	*(BYTE*)(mem + 18) = 0x10;
	
	// movabs rcx, 928182171271
	*(WORD*)(mem + 19) = 0xB948;
	*(QWORD*)(mem + 21) = (QWORD)ctx;

	// sub rsp, 28
	*(BYTE*)(mem + 29) = 0x48;
	*(BYTE*)(mem + 30) = 0x83;
	*(BYTE*)(mem + 31) = 0xEC;
	*(BYTE*)(mem + 32) = 0x28;
	// duk_push_int(ctx, argVal);
	*(BYTE*)(mem + 33) = 0xE8;
	*(DWORD*)(mem + 34) = ((QWORD)&duk_push_pointer - (mem + 33)) - 5;
	// add rsp, 28
	*(BYTE*)(mem + 38) = 0x48;
	*(BYTE*)(mem + 39) = 0x83;
	*(BYTE*)(mem + 40) = 0xC4;
	*(BYTE*)(mem + 41) = 0x28;

	// dec EDI
	*(WORD*)(mem + 42) = 0xCFFF;

	// jmp loop_args
	*(BYTE*)(mem + 44) = 0xEB;
	*(BYTE*)(mem + 45) = 0xD2;

call_duktape:
	// mov rdx, rbx
	*(BYTE*)(mem + 46) = 0x48;
	*(BYTE*)(mem + 47) = 0x89;
	*(BYTE*)(mem + 48) = 0xDA;

	// movabs rcx, 928182171271
	*(WORD*)(mem + 49) = 0xB948;
	*(QWORD*)(mem + 51) = (QWORD)ctx;

	// sub rsp, 28
	*(BYTE*)(mem + 59) = 0x48;
	*(BYTE*)(mem + 60) = 0x83;
	*(BYTE*)(mem + 61) = 0xEC;
	*(BYTE*)(mem + 62) = 0x28;
	// duk_pcall(ctx, numArgs);
	*(BYTE*)(mem + 63) = 0xE8;
	*(DWORD*)(mem + 64) = ((QWORD)&duk_pcall - (mem + 63)) - 5;
	// add rsp, 28
	*(BYTE*)(mem + 68) = 0x48;
	*(BYTE*)(mem + 69) = 0x83;
	*(BYTE*)(mem + 70) = 0xC4;
	*(BYTE*)(mem + 71) = 0x28;

	// add RSP, 16
	*(BYTE*)(mem + 72) = 0x48;
	*(BYTE*)(mem + 73) = 0x83;
	*(BYTE*)(mem + 74) = 0xC4;
	*(BYTE*)(mem + 75) = 0x10;

	// POP RBP
	*(BYTE*)(mem + 76) = 0x5D;

	// RET
	*(BYTE*)(mem + 77) = 0xC3;

	return (void*)mem_start;
}

duk_ret_t createRedirection(duk_context *ctx)
{
	void* mem = CreateJSRedirect();

	int n = duk_get_top(ctx);  /* #args */

	// Address
	QWORD address = (QWORD)duk_to_pointer(ctx, 0);

	// Number of parameters
	int numArgs = duk_to_int(ctx, 1);

	// Name
	const char* duk_name = duk_to_string(ctx, 2);
	char* name = new char[strlen(duk_name)];
	strcpy(name, duk_name);

	// Call convention
	CallConvention convention = (CallConvention)duk_to_int(ctx, 3);

	// Fastcall only
	//if (convention != CallConvention::FASTCALL)
	{
		//duk_push_boolean(ctx, false);
		//return 1;  /* one return value */
	}

	// Callback
	duk_dup(ctx, 4);
	duk_put_global_string(ctx, name);

	// 5 push + 1 push + 2 mov + 2 push + 5 push + 5 call + 3 retn
	DWORD_PTR codecave = (DWORD_PTR)GetNearMemory(NULL, 34);
	if (codecave == NULL)
	{
		duk_push_boolean(ctx, false);
		return 1;  /* one return value */
	}

	// mov RAX, address
	// push RAX
	*(BYTE*)(codecave + 0) = 0x48;
	*(BYTE*)(codecave + 1) = 0xB8;
	*(QWORD*)(codecave + 2) = (DWORD_PTR)codecave + 33;
	*(BYTE*)(codecave + 10) = 0x50;

	// PUSH RBP
	// MOV RBP, RSP
	*(BYTE*)(codecave + 11) = 0x55;
	*(BYTE*)(codecave + 12) = 0x48;
	*(BYTE*)(codecave + 13) = 0x89;
	*(BYTE*)(codecave + 14) = 0xE5;

	// PUSH numArgs
	*(BYTE*)(codecave + 15) = 0x6A;
	*(BYTE*)(codecave + 16) = numArgs;

	// PUSH name
	*(BYTE*)(codecave + 17) = 0x48;
	*(BYTE*)(codecave + 18) = 0xB8;
	*(QWORD*)(codecave + 19) = (QWORD)name;
	*(BYTE*)(codecave + 27) = 0x50;

	// JMP WrapJS
	QWORD currentAddr = codecave + 28;
	*(BYTE*)(currentAddr) = 0xE9;
	*(DWORD*)(currentAddr + 1) = ((DWORD_PTR)mem - currentAddr) - 5;

	// ret
	*(BYTE*)(codecave + 33) = 0xC3;

	// jmp codecave
	// CreateHook((void*)address, (void*)codecave, false);

	// Unprotect address
	DWORD oldProtect;
	VirtualProtect((LPVOID)address, 12, PAGE_EXECUTE_READWRITE, &oldProtect);

	// JMP dest
	*(BYTE*)(address + 0) = 0x48;
	*(BYTE*)(address + 1) = 0xB8;
	*(QWORD*)(address + 2) = (DWORD_PTR)codecave;
	*(BYTE*)(address + 10) = 0xFF;
	*(BYTE*)(address + 11) = 0xE0;

	VirtualProtect((LPVOID)address, 12, oldProtect, &oldProtect);

	duk_push_boolean(ctx, true);
	return 1;  /* one return value */
}

#else
__declspec(naked) void WrapJSRedirect()
{
    // Save some registers
    __asm push EBX
    __asm push EDI

    // duk_get_global_string(ctx, currentName);
    __asm push DWORD PTR SS:[ESP + 8]           // currentName
    __asm push ctx
    __asm call duk_get_global_string
    __asm add ESP, 8                            // Pop arguments

    __asm mov EBX, DWORD PTR SS:[ESP + 12]      // EBX = numArgs
    __asm mov EDI, EBX                          // EDI = counter

    // for each argument
loop_args:
    __asm test EDI, EDI                         // Ended?
    __asm je call_duktape

    // Cada parametro = 4 bytes ... 1, 2, 3 * 4 = 4, 8, 12 ...
    __asm mov EAX, 4
    __asm imul EAX, EDI
    __asm mov EAX, DWORD PTR SS:[EBP + 8 + EAX] // PUSH ret + PUSH EBP

    // duk_push_int(ctx, argVal);
    __asm push EAX
    __asm push ctx
    __asm call duk_push_int
    __asm add ESP, 8                            // Pop arguments

    __asm dec EDI
    __asm jmp loop_args

call_duktape:
    //duk_pcall(ctx, numArgs);
    __asm push EBX
    __asm push ctx
    __asm call duk_pcall
    __asm add ESP, 8                            // Pop arguments

    // Get returned value
    __asm push -1
    __asm push ctx
    __asm call duk_to_int
    __asm add ESP, 8                            // Pop arguments

    // Restore resigters
    __asm pop EDI
    __asm pop EBX

    // Pop currentName, numArgs
    __asm add ESP, 8

    // Restore EBP
    __asm pop EBP

    // Return to fake address
    __asm ret
}

duk_ret_t createRedirection(duk_context *ctx)
{
    int n = duk_get_top(ctx);  /* #args */

    // Address
    DWORD address = (DWORD)duk_to_int(ctx, 0);

    // Number of parameters
    int numArgs = duk_to_int(ctx, 1);

    // Name
    const char* duk_name = duk_to_string(ctx, 2);
    char* name = new char[strlen(duk_name)];
    strcpy(name, duk_name);

    // Call convention
    CallConvention convention = (CallConvention)duk_to_int(ctx, 3);

    // Fastcall not yet implemented
    if (convention == CallConvention::FASTCALL)
    {
        duk_push_boolean(ctx, false);
        return 1;  /* one return value */
    }

    // Callback
    duk_dup(ctx, 4);
    duk_put_global_string(ctx, name);

    // 5 push + 1 push + 2 mov + 2 push + 5 push + 5 call + 3 retn
    DWORD codecave = (DWORD)VirtualAlloc(NULL, 23, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (codecave == NULL)
    {
        duk_push_boolean(ctx, false);
        return 1;  /* one return value */
    }

    // PUSH retPoint (codecave + 20)
    *(BYTE*)(codecave + 0) = 0x68;
    *(DWORD*)(codecave + 1) = codecave + 20;

    // PUSH EBP
    // MOV EBP, ESP
    *(BYTE*)(codecave + 5) = 0x55;
    *(WORD*)(codecave + 6) = 0xEC8B;

    // PUSH numArgs
    *(BYTE*)(codecave + 8) = 0x6A;
    *(BYTE*)(codecave + 9) = numArgs;

    // PUSH name
    *(BYTE*)(codecave + 10) = 0x68;
    *(DWORD*)(codecave + 11) = (DWORD)name;

    // JMP WrapJS
    DWORD currentAddr = codecave + 15;
    *(BYTE*)(currentAddr) = 0xE9;
    *(DWORD*)(currentAddr + 1) = ((DWORD)&WrapJSRedirect - currentAddr) - 5;

    // RETN args*4
    if (convention == CallConvention::STDCALL)
    {
        *(BYTE*)(codecave + 20) = 0xC2;
        *(WORD*)(codecave + 21) = numArgs * 4;
    }
    else if (convention == CallConvention::CDECLCALL)
    {
        *(BYTE*)(codecave + 20) = 0xC3;
    }

    CreateHook((void*)address, (void*)codecave, false);
    duk_push_boolean(ctx, true);
    return 1;  /* one return value */
}

#endif
