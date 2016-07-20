#include "redirect.hpp"
#include "helpers.hpp"
#include "asm.hpp"

#include <Windows.h>
#include <Psapi.h>

MemoryFunction* redirectDetour = nullptr;

#ifdef BUILD_64

typedef DWORD_PTR QWORD;

MemoryFunction* getRedirect(Allocator* allocator)
{
	if (!redirectDetour)
	{
		redirectDetour = new MemoryFunction(allocator, 245);
		MemoryFunction& fn = *redirectDetour;

		push_rdx(fn);
		push_rcx(fn);
		mov_rdx_qword_ptr_rsp(fn, 0x10);
		mov_rcx_abs(fn, (uint64_t)ctx);

		call(fn, duk_get_global_string);

		mov_rbx_qword_ptr_rsp(fn, 0x18);

		mov_edi_ebx(fn);

		// Arguments 1 & 2 (RCX & RDX)
		for (int i = 0; i < 2; ++i)
		{
			// if (num_args > 0) {
				test_edi_edi(fn);
				je_short(fn, 30);

				pop_rdx(fn);
				mov_rcx_abs(fn, (uint64_t)ctx);
				call(fn, duk_push_pointer);

				dec_edi(fn);

				jmp_short(fn, 3);
			// }
			// else {
				pop_rcx(fn);
			// }
		}

		// Arguments 3 & 4 (R8 & R9)
		for (int i = 0; i < 2; ++i)
		{
			// if (num_args > 0) {
				test_edi_edi(fn);
				je_short(fn, 30);

				mov_rdx_r8(fn);
				mov_rcx_abs(fn, (uint64_t)ctx);
				call(fn, duk_push_pointer);

				dec_edi(fn);
			// }
		}

		// For each argument (>= 5)
		// {
			test_edi_edi(fn);
			je_short(fn, 45);

			// Cada parametro = 8 bytes ... 1, 2, 3 * 8 = 8, 16, 24 ...
			mov_rax_abs(fn, (uint32_t)8);
			push_rax(fn);
			imul_eax_edi(fn);

			mov_rdx_qword_ptr_rbp_rax(fn, 0x10);
			mov_rcx_abs(fn, (uint64_t)ctx);
			call(fn, duk_push_pointer);

			dec_edi(fn);

			jmp_short(fn, -45);
		//}

		// call duktape
		mov_rdx_rbx(fn);
		mov_rcx_abs(fn, (uint64_t)ctx);
		call(fn, duk_pcall);

		// Stack cleanup
		add_rsp_abs(fn, 0x10);
		pop_rbp(fn);

		// RET
		ret(fn);
	}

	return redirectDetour;
}

duk_ret_t createRedirection(duk_context *ctx)
{
	Allocator* allocator = new Allocator();
	MemoryFunction* mem = getRedirect(allocator);

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
	MemoryFunction* codecave_ptr = new MemoryFunction(allocator, 34);
	MemoryFunction& codecave = *codecave_ptr;

	if (codecave.get() == NULL)
	{
		duk_push_boolean(ctx, false);
		return 1;  /* one return value */
	}

	// Setup return point
	mov_rax_abs(codecave, (uint64_t)codecave.get() + 33);
	push_rax(codecave);

	push_rbp(codecave);
	mov_rbp_rsp(codecave);

	// PUSH numArgs
	push(codecave, (uint8_t)numArgs);

	// PUSH name
	mov_rax_abs(codecave, (uint64_t)name);
	push_rax(codecave);

	// JMP WrapJS
	jmp_long(codecave, mem->start());

	// ret
	ret(codecave);

	// jmp codecave
	// CreateHook((void*)address, (void*)codecave, false);

	// Unprotect address
	DWORD oldProtect;
	VirtualProtect((LPVOID)address, 12, PAGE_EXECUTE_READWRITE, &oldProtect);

	// JMP dest
	*(BYTE*)(address + 0) = 0x48;
	*(BYTE*)(address + 1) = 0xB8;
	*(QWORD*)(address + 2) = (DWORD_PTR)codecave.start();
	*(BYTE*)(address + 10) = 0xFF;
	*(BYTE*)(address + 11) = 0xE0;

	VirtualProtect((LPVOID)address, 12, oldProtect, &oldProtect);

	duk_push_boolean(ctx, true);
	return 1;  /* one return value */
}

#else

MemoryFunction* getRedirect(Allocator* allocator)
{
	if (!redirectDetour)
	{
		redirectDetour = new MemoryFunction(allocator, 245);
		MemoryFunction& fn = *redirectDetour;

		push_ebx(fn);
		push_edi(fn);

		push_dword_ptr_esp(fn, 8);
		push(fn, (uint32_t)ctx);
		call(fn, duk_get_global_string);
		add_esp(fn, 8);

		mov_ebx_dword_ptr_esp(fn, 12);
		mov_edi_ebx(fn);

		// for each argument
		// {
			test_edi_edi(fn);
			je_short(fn, 32);

			// Cada parametro = 4 bytes ... 1, 2, 3 * 4 = 4, 8, 12 ...
			mov_eax_abs(fn, 4);
			imul_eax_edi(fn);
			mov_eax_dword_ptr_ebp_eax(fn, 8);

			// duk_push_int(ctx, argVal);
			push_eax(fn);
			push(fn, (uint32_t)ctx);
			call(fn, duk_push_pointer);
			add_esp(fn, 8);

			dec_edi(fn);
			jmp_short(fn, -32);
		// }

		push_ebx(fn);
		push(fn, (uint32_t)ctx);
		call(fn, duk_pcall);
		add_esp(fn, 8);

		push(fn, (uint8_t)-1);
		push(fn, (uint32_t)ctx);
		call(fn, duk_to_int);
		add_esp(fn, 8);

		pop_edi(fn);
		pop_ebx(fn);
		add_esp(fn, 8);
		pop_ebp(fn);
		ret(fn);
	}

	return redirectDetour;
}

duk_ret_t createRedirection(duk_context *ctx)
{
	Allocator* allocator = new Allocator();
	MemoryFunction* mem = getRedirect(allocator);

    int n = duk_get_top(ctx);  /* #args */

    // Address
    DWORD address = (DWORD)duk_to_pointer(ctx, 0);

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
	MemoryFunction* codecave_ptr = new MemoryFunction(allocator, 23);
	MemoryFunction& codecave = *codecave_ptr;
    if (codecave.get() == NULL)
    {
        duk_push_boolean(ctx, false);
        return 1;  /* one return value */
    }

	// Fake return point
	push(codecave, (uint32_t)codecave.get() + 20);

	// Save stack pointer
	push_ebp(codecave);
	mov_ebp_esp(codecave);

    // PUSH numArgs
	push(codecave, (uint8_t)numArgs);

    // PUSH name
	push(codecave, (uint32_t)name);

    // JMP WrapJS
	jmp_long(codecave, mem->start());

    // RETN args*4
    if (convention == CallConvention::STDCALL)
    {
		retn(codecave, numArgs);
    }
    else if (convention == CallConvention::CDECLCALL)
    {
		ret(codecave);
    }

    CreateHook((void*)address, (void*)codecave.start(), false);
    duk_push_boolean(ctx, true);
    return 1;  /* one return value */
}

#endif
