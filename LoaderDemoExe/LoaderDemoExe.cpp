// LoaderDemoExe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <strsafe.h>

#include "..\mmLoader\mmLoader.h"

int _tmain(int argc, _TCHAR* argv[])
{
	MessageBox(NULL, _T("Exe Withou CRT lib."), _T("OK"), MB_OK);

	TCHAR tszDllPath[] = _T("F:\\RtlExUpd.dll");

	MEM_MODULE sMemModule;
	RtlZeroMemory(&sMemModule, sizeof(sMemModule));
	sMemModule.RawFile.h = INVALID_HANDLE_VALUE;

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

	sMemModule.pNtFuncptrsTable = &sNtFuncPtrsTable;

	TCHAR tszFormat[] = _T("Address of ShowLastError: %p");
	TCHAR tszText[MAX_PATH];
	RtlZeroMemory(tszText, sizeof(tszText));

	//////////////////////////////////////////////////////////////////////////
	// 先使用原始函数Test

	//if (LoadMemModule(&sMemModule, tszDllPath, FALSE))
	if (MemModuleHelper(&sMemModule, MHM_BOOL_LOAD, tszDllPath, NULL, FALSE))
	{
		//LPVOID lpAddr = (LPVOID)GetMemModuleProc(&sMemModule, "SetCDfmt");
		LPVOID lpAddr = (LPVOID)MemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "SetCDfmt", FALSE);
		
		StringCchPrintf(tszText, _countof(tszText), tszFormat, lpAddr);

		MessageBox(NULL, tszText, NULL, MB_OK);

		//FreeMemModule(&sMemModule);
		MemModuleHelper(&sMemModule, MHM_VOID_FREE, NULL, NULL, FALSE);
	}


	// 把ShellCode 拷贝到任意内存地址再进行测试

	DWORD dwShellCodeLen = 0;
	dwShellCodeLen = (DWORD)mmLoaderSCEnd - (DWORD)mmLoaderSCStart;

	LPVOID lpShellCodeBase = VirtualAlloc(
		NULL, 
		dwShellCodeLen, 
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE);

	if (NULL == lpShellCodeBase)
	{
		MessageBox(NULL, _T("为ShellCode分配内存空间失败!"), NULL, MB_OK);
		return FALSE;
	}

	RtlCopyMemory(lpShellCodeBase, mmLoaderSCStart, dwShellCodeLen);

	Type_MemModuleHelper pfnMemModuleHelper = (Type_MemModuleHelper)lpShellCodeBase;

	if (pfnMemModuleHelper(&sMemModule, MHM_BOOL_LOAD, tszDllPath, NULL, FALSE))
	{
		LPVOID lpAddr = (LPVOID)pfnMemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "SetCDfmt", FALSE);

		StringCchPrintf(tszText, _countof(tszText), tszFormat, lpAddr);

		MessageBox(NULL, tszText, NULL, MB_OK);

		pfnMemModuleHelper(&sMemModule, MHM_VOID_FREE, NULL, NULL, FALSE);
	}

	VirtualFree(lpShellCodeBase, 0, MEM_RELEASE);


	// 直接使用提取出来的ShellCode测试！
	lpShellCodeBase = VirtualAlloc(
		NULL, 
		sizeof(mmLoaderShellCode), 
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE);

	if (NULL == lpShellCodeBase)
	{
		MessageBox(NULL, _T("为ShellCode分配内存空间失败!"), NULL, MB_OK);
		return FALSE;
	}

	RtlCopyMemory(lpShellCodeBase, mmLoaderShellCode, sizeof(mmLoaderShellCode));

	pfnMemModuleHelper = (Type_MemModuleHelper)lpShellCodeBase;

	if (pfnMemModuleHelper(&sMemModule, MHM_BOOL_LOAD, tszDllPath, NULL, FALSE))
	{
		LPVOID lpAddr = (LPVOID)pfnMemModuleHelper(&sMemModule, MHM_FARPROC_GETPROC, NULL, "SetCDfmt", FALSE);

		StringCchPrintf(tszText, _countof(tszText), tszFormat, lpAddr);

		MessageBox(NULL, tszText, NULL, MB_OK);

		pfnMemModuleHelper(&sMemModule, MHM_VOID_FREE, NULL, NULL, FALSE);
	}

	VirtualFree(lpShellCodeBase, 0, MEM_RELEASE);

	return 0;
}

