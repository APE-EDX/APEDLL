#include "socket.hpp"
#include "utils.hpp"

#include <Windows.h>
#include <duktape.h>
#include <apecore.hpp>

HINSTANCE dllhandle;

BOOL WINAPI DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved)
{
	CreateConsole();

    if (reason == DLL_PROCESS_ATTACH)
    {
		// Save handle
		dllhandle = handle;

		// Initialize APECore
		duk_context* ctx = apecore_initialize([](duk_context* ctx) -> void {

			// Add CreateConsole
			duk_push_c_function(ctx, WrapCreateConsole, DUK_VARARGS);
			duk_put_global_string(ctx, "CreateConsole");

		});
    }

    if (reason == DLL_PROCESS_DETACH)
    {
		apecore_deinitialize();
    }

    return TRUE;
}
