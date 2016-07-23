#include "socket.hpp"

#include <Windows.h>
#include <duktape.h>
#include <vector>

#include "utils.hpp"
#include "helpers.hpp"
#include "redirect.hpp"

duk_context *ctx = nullptr;
ClientSocket* clientSocket = nullptr;
HINSTANCE dllhandle;

void require(duk_context* ctx, char* base_path, char* override_path, char* file)
{
    // Override with the API file
    strcpy(override_path, file);

    // Load it to duktape
    duk_push_object(ctx);
    duk_eval_file(ctx, base_path);
}

static void SocketRecv(ClientSocket* clientSocket)
{
    duk_idx_t thr_idx;
    duk_context *new_ctx;

    thr_idx = duk_push_thread(ctx);
    new_ctx = duk_get_context(ctx, thr_idx);

    while (1)
    {
        std::string buffer = clientSocket->recv();

        duk_push_global_object(new_ctx);
        duk_get_prop_string(new_ctx, -1, "onMessage");
        duk_push_string(new_ctx, buffer.c_str());
        duk_pcall(new_ctx, 1);
    }
}

BOOL WINAPI DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) // Self-explanatory
    {
		// Save handle
		dllhandle = handle;

        // Create socket
        clientSocket = new ClientSocket(AF_INET, SOCK_STREAM, 0);
        clientSocket->connect("127.0.0.1", 25100);

        if (clientSocket->lastError() != SocketError::NONE)
        {
            printf("ERROR SOCKET %d\n", clientSocket->lastError());
        }
        else
        {
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SocketRecv, clientSocket, 0, NULL);
        }

        DisableThreadLibraryCalls(handle);
        ctx = duk_create_heap_default();

        // Allow setHook to be called from inside JS
		InitializeDuktape_Redirect(ctx);

		duk_push_c_function(ctx, sizeOfPtr, 0);
		duk_put_global_string(ctx, "ptrSize");

        duk_push_c_function(ctx, addressOf, DUK_VARARGS);
        duk_put_global_string(ctx, "cpp_addressOf");

		duk_push_c_function(ctx, charCodeAt, DUK_VARARGS);
		duk_put_global_string(ctx, "cpp_charCodeAt");

		duk_push_c_function(ctx, writeMemory, DUK_VARARGS);
		duk_put_global_string(ctx, "cpp_writeMemory");

		duk_push_c_function(ctx, readMemory, DUK_VARARGS);
		duk_put_global_string(ctx, "cpp_readMemory");

		duk_push_c_function(ctx, readString, DUK_VARARGS);
		duk_put_global_string(ctx, "cpp_readString");

        duk_push_c_function(ctx, WrapCreateConsole, DUK_VARARGS);
        duk_put_global_string(ctx, "CreateConsole");

        // Get current path
        char path[MAX_PATH];
        size_t len = GetModuleFileNameA(handle, path, sizeof(path));

        // Find last / and
        while (len > 0 && path[--len] != '\\') {};
        if (len > 0)
        {
            // Overwrite path from here on
            char* override_from = &path[len + 1];

            // Add all API files
            require(ctx, path, override_from, "../../jsAPI/eval_js.js");
            require(ctx, path, override_from, "../../jsAPI/call_convention.js");
            require(ctx, path, override_from, "../../jsAPI/ptr.js");
            require(ctx, path, override_from, "../../jsAPI/find.js");
            require(ctx, path, override_from, "../../jsAPI/redirect.js");

            // Custom user init code
            require(ctx, path, override_from, "../../init.js");
        }
        else
        {
            // Notify of error via protocol
        }
    }

    if (reason == DLL_PROCESS_DETACH) // Self-explanatory
    {
        duk_destroy_heap(ctx);
    }

    return TRUE;
}
