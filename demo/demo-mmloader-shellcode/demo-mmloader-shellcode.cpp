// demo-mmloader-shellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "mmLoaderShellCode.h"

int main()
{
	// Function table
	NTFUNCPTRSTABLE sNtFuncPtrsTable;
	sNtFuncPtrsTable.pfnCreateFileW = CreateFileW;
	sNtFuncPtrsTable.pfnGetFileSize = GetFileSize;
	sNtFuncPtrsTable.pfnCreateFileMappingW = CreateFileMappingW;
	sNtFuncPtrsTable.pfnMapViewOfFile = MapViewOfFile;
	sNtFuncPtrsTable.pfnUnmapViewOfFile = UnmapViewOfFile;
	sNtFuncPtrsTable.pfnCloseHandle = CloseHandle;
	sNtFuncPtrsTable.pfnGetModuleHandleA = GetModuleHandleA;
	sNtFuncPtrsTable.pfnLoadLibraryA = LoadLibraryA;
	sNtFuncPtrsTable.pfnGetProcAddress = GetProcAddress;
	sNtFuncPtrsTable.pfnVirtualAlloc = VirtualAlloc;
	sNtFuncPtrsTable.pfnVirtualFree = VirtualFree;
	sNtFuncPtrsTable.pfnVirtualProtect = VirtualProtect;

	// Memory module
	MEM_MODULE sMemModule;
	sMemModule.RawFile.h = INVALID_HANDLE_VALUE;
	sMemModule.pNtFuncptrsTable = &sNtFuncPtrsTable;

	// Allocate memory buffer for shell code with EXECUTE privilege
	LPVOID  lpShellCodeBase = ::VirtualAlloc(
		NULL,
		sizeof(mmLoaderShellCode),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	if (NULL == lpShellCodeBase)
	{
		::_tprintf(_T("Failed to allocate space for ShellCode!"));
		return FALSE;
	}

	// Copy shell code to the executable memory buffer
	::RtlCopyMemory(lpShellCodeBase, mmLoaderShellCode, sizeof(mmLoaderShellCode));

	// Get the helper function 
	Type_MemModuleHelper pfnMemModuleHelper = (Type_MemModuleHelper)lpShellCodeBase;

	// Load the module
	WCHAR wszDllPath[] = L"demo-module.dll";
	if (pfnMemModuleHelper(&sMemModule, MHM_BOOL_LOAD, wszDllPath, NULL, FALSE))
	{
		_tprintf(_T("Module was load successfully. Module Base: 0x%p!\r\n"), sMemModule.lpBase);

		// Get address of function demoFunction
		LPVOID lpAddr = (LPVOID)pfnMemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "demoFunction", FALSE);
		if (lpAddr)
		{
			_tprintf(_T("Get address of demoFunction successfully. Address: 0x%p!\r\n"), lpAddr);

			// Function pointer type of demoFunction
			typedef int (WINAPI * Type_TargetFunction)();

			// Call the demoFunction
			Type_TargetFunction pfnFunction = (Type_TargetFunction)lpAddr;
			pfnFunction();
		}
		else
			_tprintf(_T("Failed to get address of MessageBoxA from memory module."));

		// Free the module
		pfnMemModuleHelper(&sMemModule, MHM_VOID_FREE, NULL, NULL, FALSE);
	}
	else
		_tprintf(_T("Failed to load user32.dll!\r\n"));

	// Free the memory buffer of the shell code
	::VirtualFree(lpShellCodeBase, 0, MEM_RELEASE);

	return 0;
}
