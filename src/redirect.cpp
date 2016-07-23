#include "redirect.hpp"
#include "helpers.hpp"
#include "asm.hpp"

#include <Windows.h>
#include <Psapi.h>

Allocator* allocator = new Allocator();
MemoryFunction* redirectDetour = nullptr;
MemoryFunction* redirectCallorigin = nullptr;

#ifdef BUILD_64

typedef DWORD_PTR QWORD;

MemoryFunction* getRedirect(Allocator* allocator)
{
	if (!redirectDetour)
	{
		redirectDetour = new MemoryFunction(allocator, 245);
		MemoryFunction& fn = *redirectDetour;

		push_rbx(fn);
		push_rdi(fn);

		push_r9(fn);
		push_r8(fn);
		push_rdx(fn);
		push_rcx(fn);
		mov_rdx_qword_ptr_rsp(fn, 0x30);
		mov_rcx_abs(fn, (uint64_t)ctx);

		call(fn, duk_get_global_string);

		mov_rbx_qword_ptr_rsp(fn, 0x38);

		mov_edi_ebx(fn);

		// Arguments 1 & 2 & 3 & 4 (RCX & RDX & R8 & R9)
		for (int i = 0; i < 4; ++i)
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

		xor_r10_r10(fn);

		// FIXME: This loop is inverted... see the 32 bits implementation
		// For each argument (>= 5)
		// {
			cmp_r10_rdi(fn);
			je_short(fn, 50);

			// Cada parametro = 8 bytes ... 1, 2, 3 * 8 = 8, 16, 24 ...
			mov_rax_abs(fn, (uint32_t)8);
			imul_rax_r10(fn);

			mov_rdx_qword_ptr_rbp_rax(fn, 0x10 + 0x28); // 0x10 from previous pushes, 0x28 from shadow stack + ret
			mov_rcx_abs(fn, (uint64_t)ctx);
			push_r10(fn);
			call(fn, duk_push_pointer);
			pop_r10(fn);

			inc_r10(fn);

			jmp_short(fn, -51);
		//}

		// call duktape
		mov_rdx_rbx(fn);
		mov_rcx_abs(fn, (uint64_t)ctx);
		call(fn, duk_pcall);

		// Get returned value
		mov_rdx_abs(fn, -1);
		mov_rcx_abs(fn, (uint64_t)ctx);
		call(fn, duk_to_pointer);

		// Stack cleanup
		pop_rdi(fn);
		pop_rbx(fn);
		add_rsp_abs(fn, 0x10); // pushed name + args
		pop_rbp(fn);

		// RET
		ret(fn);
	}

	return redirectDetour;
}

duk_ret_t initializeRedirection(duk_context *ctx)
{
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

	int len = 12;
	if (n > 5)
	{
		len = duk_to_int(ctx, 5);
	}
	else
	{
		// Static analysis to find the number of bytes
	}

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

	// Save stack pointer
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


	////////////////////
	MemoryFunction* call_org_ptr = new MemoryFunction(allocator, 23);
	MemoryFunction& call_org = *call_org_ptr;

	push_rbp(call_org);
	mov_rbp_rsp(call_org);

	for (int i = 0; i < numArgs; ++i)
	{
		push_rcx(call_org);
		mov_rdx_abs(call_org, i);
		call(call_org, duk_to_pointer);
		pop_rcx(call_org);

		push_rax(call_org);
	}

	if (numArgs > 0)
	{
		mov_rcx_qword_ptr_rsp(call_org, (numArgs - 1) * 8);
	}
	if (numArgs > 1)
	{
		mov_rdx_qword_ptr_rsp(call_org, (numArgs - 2) * 8);
	}
	if (numArgs > 2)
	{
		mov_r8_qword_ptr_rsp(call_org, (numArgs - 3) * 8);
	}
	if (numArgs > 3)
	{
		mov_r9_qword_ptr_rsp(call_org, (numArgs - 4) * 8);
	}

	// Shadow space
	sub_rsp_abs(call_org, 0x20);

	// Return point
	mov_rax_abs(call_org, (uint64_t)(call_org.get() + 28));
	push_rax(call_org);

	for (int i = 0; i < len; ++i)
	{
		call_org << *(BYTE*)(address + i);
	}
	jmp_long(call_org, (void*)(address + len));

	add_rsp_abs(call_org, numArgs * 8 + 0x20);
	pop_rbp(call_org);
	ret(call_org);

	// Get access to the default instance.
	duk_push_this(ctx);
	duk_push_pointer(ctx, (void*)call_org.start());
	duk_put_prop_string(ctx, -2, "fn_ptr");

	void* original = malloc(len);
	memcpy(original, (void*)address, len);
	duk_push_this(ctx);
	duk_push_pointer(ctx, original);
	duk_put_prop_string(ctx, -2, "fn_org_bytes");

	duk_push_this(ctx);
	duk_push_int(ctx, len);
	duk_put_prop_string(ctx, -2, "fn_org_total");

	duk_push_this(ctx);
	duk_push_pointer(ctx, (void*)address);
	duk_put_prop_string(ctx, -2, "fn_org_addr");


	// jmp codecave
	// CreateHook((void*)address, (void*)codecave, false);

	// Unprotect address
	// TODO: It's 12 not 15
	DWORD oldProtect;
	VirtualProtect((LPVOID)address, len, PAGE_EXECUTE_READWRITE, &oldProtect);

	// JMP dest
	*(BYTE*)(address + 0) = 0x48;
	*(BYTE*)(address + 1) = 0xB8;
	*(QWORD*)(address + 2) = (DWORD_PTR)codecave.start();
	*(BYTE*)(address + 10) = 0xFF;
	*(BYTE*)(address + 11) = 0xE0;

	for (int i = 12; i < len; ++i)
	{
		*(BYTE*)(address + i) = 0x90;
	}

	VirtualProtect((LPVOID)address, len, oldProtect, &oldProtect);

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

		mov_ecx_ebx(fn);
		xor_edi_edi(fn);

		// for each argument
		// {
			cmp_edi_ecx(fn);
			je_short(fn, 34);

			// Cada parametro = 4 bytes ... 1, 2, 3 * 4 = 4, 8, 12 ...
			mov_eax_abs(fn, 4);
			imul_eax_edi(fn);
			mov_eax_dword_ptr_ebp_eax(fn, 12);

			// duk_push_int(ctx, argVal);
			push_ecx(fn);
			push_eax(fn);
			push(fn, (uint32_t)ctx);
			call(fn, duk_push_pointer);
			add_esp(fn, 8);
			pop_ecx(fn);

			inc_edi(fn);
			jmp_short(fn, -34);
		// }

		push_ebx(fn);
		push(fn, (uint32_t)ctx);
		call(fn, duk_pcall);
		add_esp(fn, 8);

		push(fn, (uint8_t)-1);
		push(fn, (uint32_t)ctx);
		call(fn, duk_to_pointer);
		add_esp(fn, 8);

		pop_edi(fn);
		pop_ebx(fn);
		add_esp(fn, 8);
		pop_ebp(fn);
		ret(fn);
	}

	return redirectDetour;
}

duk_ret_t initializeRedirection(duk_context *ctx)
{
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

	int len = 5;
	if (n > 5)
	{
		len = duk_to_int(ctx, 5);
	}
	else
	{
		// Static analysis to find the number of bytes
	}

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

	////////////////////
	MemoryFunction* call_org_ptr = new MemoryFunction(allocator, 23);
	MemoryFunction& call_org = *call_org_ptr;

	mov_ecx_dword_ptr_esp(call_org, 4);
	push_ebp(call_org);
	mov_ebp_esp(call_org);

	for (int i = numArgs - 1; i >= 0; --i)
	{
		push_ecx(call_org);
		push(call_org, (uint8_t)i);
		push_ecx(call_org);
		call(call_org, duk_to_pointer);
		add_esp(call_org, 8);
		pop_ecx(call_org);

		push_eax(call_org);
	}

	// Return point
	push(call_org, (uint32_t)(call_org.get() + 15));

	for (int i = 0; i < 5; ++i)
	{
		call_org << *(BYTE*)(address + i);
	}
	jmp_long(call_org, (void*)(address + len));

	pop_ebp(call_org);

	if (convention == CallConvention::CDECLCALL)
	{
		add_esp(call_org, numArgs * 4);
	}
	ret(call_org);

	// Get access to the default instance.
	duk_push_this(ctx);
	duk_push_pointer(ctx, (void*)call_org.start());
	duk_put_prop_string(ctx, -2, "fn_ptr");

	void* original = malloc(len);
	memcpy(original, (void*)address, len);
	duk_push_this(ctx);
	duk_push_pointer(ctx, original);
	duk_put_prop_string(ctx, -2, "fn_org_bytes");

	duk_push_this(ctx);
	duk_push_int(ctx, len);
	duk_put_prop_string(ctx, -2, "fn_org_total");

	duk_push_this(ctx);
	duk_push_pointer(ctx, (void*)address);
	duk_put_prop_string(ctx, -2, "fn_org_addr");

    CreateHook((void*)address, (void*)codecave.start(), false, len);
    return 0;  /* undefined, default */
}

#endif

duk_ret_t restoreRedirection(duk_context* ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "fn_org_addr");
	void* address = duk_to_pointer(ctx, -1);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "fn_org_bytes");
	void* original = duk_to_pointer(ctx, -1);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "fn_org_total");
	int total = duk_to_int(ctx, -1);

	DWORD oldProtect;
	VirtualProtect(address, total, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(address, original, total);

	VirtualProtect(address, total, oldProtect, &oldProtect);

	duk_push_boolean(ctx, true);
	return 1;
}

duk_ret_t createRedirection(duk_context *ctx)
{
	// Make sure it is a constructor
	if (!duk_is_constructor_call(ctx))
	{
		return DUK_RET_TYPE_ERROR;
	}

	return 0;
}


char* fn_ptr = "fn_ptr";
void InitializeDuktape_Redirect(duk_context *ctx) {
	redirectCallorigin = new MemoryFunction(allocator, 20);
	MemoryFunction& fn = *redirectCallorigin;

#ifdef BUILD_64
	push_rbp(fn);
	mov_rbp_rsp(fn);

	push_rcx(fn);
	call(fn, duk_push_this);
	pop_rcx(fn);

	push_rcx(fn);
	mov_rdx_abs(fn, -1);
	mov_r8_abs(fn, (uint64_t)fn_ptr);
	call(fn, duk_get_prop_string);
	pop_rcx(fn);

	push_rcx(fn);
	mov_rdx_abs(fn, -1);
	call(fn, duk_to_pointer);
	pop_rcx(fn);

	push_rcx(fn);
	call_rax(fn);
	pop_rcx(fn);

	mov_rdx_rax(fn);
	call(fn, duk_push_pointer);

	pop_rbp(fn);
	mov_rax_abs(fn, (uint32_t)1);
	ret(fn);
#else
	mov_ecx_dword_ptr_esp(fn, 4);
	push_ebp(fn);
	mov_ebp_esp(fn);

	push_ecx(fn);
	push_ecx(fn);
	call(fn, duk_push_this);
	add_esp(fn, 4);
	pop_ecx(fn);

	push_ecx(fn);
	push(fn, (uint32_t)fn_ptr);
	push(fn, (uint32_t)-1);
	push_ecx(fn);
	call(fn, duk_get_prop_string);
	add_esp(fn, 12);
	pop_ecx(fn);

	push_ecx(fn);
	push(fn, (uint32_t)-1);
	push_ecx(fn);
	call(fn, duk_to_pointer);
	add_esp(fn, 8);
	pop_ecx(fn);

	push_ecx(fn);
	push_ecx(fn);
	call_eax(fn);
	add_esp(fn, 4);
	pop_ecx(fn);

	push_eax(fn);
	push_ecx(fn);
	call(fn, duk_push_pointer);
	add_esp(fn, 8);

	pop_ebp(fn);

	mov_eax_abs(fn, 1);
	ret(fn);
#endif

	/* Push constructor function; all Duktape/C functions are
	* "constructable" and can be called as 'new Foo()'.
	*/
	duk_push_c_function(ctx, createRedirection, DUK_VARARGS);

	/* Push MyObject.prototype object. */
	duk_push_object(ctx);

	/* Set MyObject.prototype.init. */
	duk_push_c_function(ctx, initializeRedirection, DUK_VARARGS);
	duk_put_prop_string(ctx, -2, "init");

	duk_push_c_function(ctx, restoreRedirection, DUK_VARARGS);
	duk_put_prop_string(ctx, -2, "restore");

	/* Set MyObject.prototype.fn. */
	duk_push_c_function(ctx, (duk_c_function)redirectCallorigin->start(), DUK_VARARGS);
	duk_put_prop_string(ctx, -2, "fn");

	/* Set MyObject.prototype = proto */
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "cpp_redirect");
}
