// demo-mmloader-static.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <strsafe.h>
#include "..\..\output\include\mmLoader\mmLoader.h"

int main()
{
	int iRet = -1;

	// Initialize function table
	NTFUNCPTRSTABLE sNtFuncPtrsTable;
	sNtFuncPtrsTable.pfnCreateFileW = ::CreateFileW;
	sNtFuncPtrsTable.pfnGetFileSize = ::GetFileSize;
	sNtFuncPtrsTable.pfnCreateFileMappingW = ::CreateFileMappingW;
	sNtFuncPtrsTable.pfnMapViewOfFile = ::MapViewOfFile;
	sNtFuncPtrsTable.pfnUnmapViewOfFile = ::UnmapViewOfFile;
	sNtFuncPtrsTable.pfnCloseHandle = ::CloseHandle;
	sNtFuncPtrsTable.pfnGetModuleHandleA = ::GetModuleHandleA;
	sNtFuncPtrsTable.pfnLoadLibraryA = ::LoadLibraryA;
	sNtFuncPtrsTable.pfnGetProcAddress = ::GetProcAddress;
	sNtFuncPtrsTable.pfnVirtualAlloc = ::VirtualAlloc;
	sNtFuncPtrsTable.pfnVirtualFree = ::VirtualFree;
	sNtFuncPtrsTable.pfnVirtualProtect = ::VirtualProtect;

	// Initialize MEM_MODULE
	MEM_MODULE sMemModule;
	sMemModule.RawFile.h = INVALID_HANDLE_VALUE;
	sMemModule.pNtFuncptrsTable = &sNtFuncPtrsTable;

	// Load the module
	WCHAR wszDllPath[] = L"demo-module.dll";
	if (MemModuleHelper(&sMemModule, MHM_BOOL_LOAD, wszDllPath, NULL, TRUE))
	{
		_tprintf(_T("Module was loaded successfully. Module Base: 0x%p!\r\n"), sMemModule.lpBase);

		// Get address of function demoFunction
		LPVOID lpAddr = (LPVOID)MemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "demoFunction", FALSE);
		if (lpAddr)
		{
			_tprintf(_T("Get address of demoFunction successfully. Address: 0x%p!\r\n"), lpAddr);

			// Function pointer type of demoFunction
			typedef BOOL (WINAPI * Type_TargetFunction)(unsigned char*, unsigned int);

			// Call the demoFunction
			Type_TargetFunction pfnFunction = (Type_TargetFunction)lpAddr;

			unsigned char buf[MAX_PATH] = { 0 };
			if (pfnFunction(buf, MAX_PATH))
			{
				char* p = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
				memcmp(buf, p, strlen(p));
				iRet = 0;
			}
		}
		else
			_tprintf(_T("Failed to get address of demoFunction from memory module.\r\n"));

		// Free the module
		MemModuleHelper(&sMemModule, MHM_VOID_FREE, NULL, NULL, FALSE);
	}
	else
		_tprintf(_T("Failed to load the module!\r\n"));

	return iRet;
}

