// demo-mmloader-shellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#ifdef _WIN64
#	ifdef _DEBUG
#		include "mmLoader/mmLoaderShellCode-x64-Debug.h"
#	else
#		include "mmLoader/mmLoaderShellCode-x64-Release.h"
#	endif
#else
#	ifdef _DEBUG
#		include "mmLoader/mmLoaderShellCode-x86-Debug.h"
#	else
#		include "mmLoader/mmLoaderShellCode-x86-Release.h"
#	endif
#endif

int main()
{
	int iRet = -1;

	// Initialize function table
	NTFUNCPTRSTABLE sNtFuncPtrsTable;
	sNtFuncPtrsTable.pfnGetModuleHandleA = ::GetModuleHandleA;
	sNtFuncPtrsTable.pfnLoadLibraryA = ::LoadLibraryA;
	sNtFuncPtrsTable.pfnGetProcAddress = ::GetProcAddress;
	sNtFuncPtrsTable.pfnVirtualAlloc = ::VirtualAlloc;
	sNtFuncPtrsTable.pfnVirtualFree = ::VirtualFree;
	sNtFuncPtrsTable.pfnVirtualProtect = ::VirtualProtect;

	// Memory module
	MEM_MODULE sMemModule;
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
		return iRet;
	}

	// Copy shell code to the executable memory buffer
	::RtlCopyMemory(lpShellCodeBase, mmLoaderShellCode, sizeof(mmLoaderShellCode));

	// Get the helper function 
	Type_MemModuleHelper pfnMemModuleHelper = (Type_MemModuleHelper)lpShellCodeBase;

	// Load the module
#ifdef _DEBUG
	WCHAR wszDllPath[] = L"demo-moduled.dll";
#else
	WCHAR wszDllPath[] = L"demo-module.dll";
#endif

	// Open the module and read it into memory buffer
	BOOL br = FALSE;
	HANDLE hFile = ::CreateFileW(wszDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile || NULL == hFile)
	{
		wprintf(L"Failed to open the file: %s\r\n", wszDllPath);
		return iRet;
	}

	// Check file size
	DWORD dwFileSize = ::GetFileSize(hFile, NULL);
	if (INVALID_FILE_SIZE == dwFileSize || dwFileSize < sizeof(IMAGE_DOS_HEADER))
	{
		::CloseHandle(hFile);
		_tprintf(_T("Invalid file size: %d\r\n"), dwFileSize);
		return iRet;
	}

	HANDLE hFileMapping = ::CreateFileMappingW(hFile, 0, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hFileMapping)
	{
		::CloseHandle(hFile);
		_tprintf(_T("Failed to create file mapping.\r\n"));
		return iRet;
	}

	LPVOID pBuffer = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pBuffer)
	{
		::CloseHandle(hFileMapping);
		::CloseHandle(hFile);
		_tprintf(_T("Failed to map view of the file.\r\n"));
		return iRet;
	}

	if (pfnMemModuleHelper(&sMemModule, MHM_BOOL_LOAD, pBuffer, NULL, FALSE))
	{
		::UnmapViewOfFile(pBuffer);
		::CloseHandle(hFileMapping);
		::CloseHandle(hFile);

		_tprintf(_T("Module was load successfully. Module Base: 0x%p!\r\n"), sMemModule.lpBase);

		// Get address of function demoFunction
		LPVOID lpAddr = (LPVOID)pfnMemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "demoFunction", FALSE);
		if (lpAddr)
		{
			_tprintf(_T("Get address of demoFunction successfully. Address: 0x%p!\r\n"), lpAddr);

			// Function pointer type of demoFunction
			typedef BOOL(__stdcall * Type_TargetFunction)(unsigned char*, unsigned int);

			// Call the demoFunction
			Type_TargetFunction pfnFunction = (Type_TargetFunction)lpAddr;

			unsigned char buf[MAX_PATH] = { 0 };
			if (pfnFunction(buf, MAX_PATH))
			{
				char* p = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
				iRet = ::memcmp(buf, p, strlen(p));
				if (0 == iRet)
					_tprintf(_T("Called target function demoFunction successfully with correct return value!\r\n"));
				else
					_tprintf(_T("Called target function demoFunction successfully, but returned unexpected value!\r\n"));
			}
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

	return iRet;
}
