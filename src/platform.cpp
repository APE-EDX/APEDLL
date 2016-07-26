#include "platform.h"

#include <apecore.hpp>
#include <Windows.h>
#include <Psapi.h>


extern HINSTANCE dllhandle;

const uint32_t toVirtualProtect(MemoryProtect protect)
{
	switch (protect)
	{
		case MemoryProtect::READ:				return PAGE_READONLY;
		case MemoryProtect::READWRITE:			return PAGE_READWRITE;
		case MemoryProtect::EXECUTE:			return PAGE_EXECUTE;
		case MemoryProtect::EXECUTE_READ:		return PAGE_EXECUTE_READ;
		case MemoryProtect::EXECUTE_READWRITE:	return PAGE_EXECUTE_READWRITE;
	}

	return 0;
}

const MemoryProtect toMemoryProtect(uint32_t protect)
{
	switch (protect)
	{
		case PAGE_READONLY:				return MemoryProtect::READ;
		case PAGE_READWRITE:			return MemoryProtect::READWRITE;
		case PAGE_EXECUTE:				return MemoryProtect::EXECUTE;
		case PAGE_EXECUTE_READ:			return MemoryProtect::EXECUTE_READ;
		case PAGE_EXECUTE_READWRITE:	return MemoryProtect::EXECUTE_READWRITE;
	}

	return MemoryProtect::EXECUTE_READ;
}

bool createThread(ThreadFunction function, void* parameter)
{
	return CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)function, parameter, 0, NULL) != NULL;
}

size_t getLibraryPath(char* buffer, size_t size)
{
	return GetModuleFileNameA(dllhandle, buffer, size);
}

void* getLibraryOEP()
{
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), dllhandle, &modInfo, sizeof(MODULEINFO));
	return modInfo.EntryPoint;
}

uint32_t getLibrarySize()
{
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), dllhandle, &modInfo, sizeof(MODULEINFO));
	return modInfo.SizeOfImage;
}

VirtualState virtualMemoryState(void* address)
{
	MEMORY_BASIC_INFORMATION mi = { 0 };
	VirtualQuery(address, &mi, sizeof(mi));

	return (mi.State == MEM_FREE) ? VirtualState::FREE : VirtualState::RESERVED;
}

void* virtualMemoryCommit(void* address, size_t size, MemoryProtect protect)
{
	return VirtualAlloc(address, size, MEM_RESERVE | MEM_COMMIT, toVirtualProtect(protect));
}

bool virtualMemoryProtect(void* address, size_t size, MemoryProtect protect, MemoryProtect* old)
{
	DWORD oldVirtual;
	BOOL result = VirtualProtect(address, size, toVirtualProtect(protect), &oldVirtual);

	if (old)
	{
		*old = toMemoryProtect(oldVirtual);
	}

	return result == TRUE;
}

void* methodAddress(const char* library, const char* method)
{
	return GetProcAddress(GetModuleHandleA(library), method);
}
