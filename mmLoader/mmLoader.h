/********************************************************************
	created:	2014/03/11
	created:	11:3:2014   14:03
	file base:	mmLoader
	file ext:	h
	author:		tishion
	
	purpose:	
*********************************************************************/
#ifndef __MMLOADER_H_INCLUDED_
#define __MMLOADER_H_INCLUDED_

//////////////////////////////////////////////////////////////////////////
// Function pointer table
typedef struct __NTFUNCPTRS
{
	LPVOID pfnCreateFileW;			//CreateFileW
	LPVOID pfnGetFileSize;			//GetFileSize
	LPVOID pfnCreateFileMappingW;	//CreateFileMappingW
	LPVOID pfnMapViewOfFile;		//MapViewOfFile
	LPVOID pfnUnmapViewOfFile;		//UnmapViewOfFile
	LPVOID pfnCloseHandle;			//CloseHandle
	LPVOID pfnGetModuleHandleA;		//GetModuleHandleA
	LPVOID pfnLoadLibraryA;			//LoadLibraryA
	LPVOID pfnGetProcAddress;		//GetProcAddress
	LPVOID pfnVirtualAlloc;			//VirtualAlloc
	LPVOID pfnVirtualFree;			//VirtualFree
	LPVOID pfnVirtualProtect;		//VirtualProtect
	LPVOID pfnReversed_0;
	LPVOID pfnReversed_1;
	LPVOID pfnReversed_2;
	LPVOID pfnReversed_3;
	LPVOID pfnReversed_4;
}NTFUNCPTRSTABLE, *PNTFUNCPTRSTABLE;

//////////////////////////////////////////////////////////////////////////
// MemModuleObject
typedef struct __MEMMODULE
{
	union								// MemModule base
	{
		DWORD	dwBase;
		HMODULE	hModule;
		LPVOID	lpBase;
		PIMAGE_DOS_HEADER pImageDosHeader;
	};
	DWORD dwSizeOfImage;				// MemModule size
	DWORD dwCrc;						// MemModule crc32

	BOOL	bLoadOk;					// MemModule is load ok?

	PNTFUNCPTRSTABLE pNtFuncptrsTable;	// Pointer to NT function pointers table 

	struct								// Raw file resource data
	{
		HANDLE	h;
		HANDLE	hMapping;
		LPVOID	pBuffer;
	}RawFile;

	TCHAR tszModuleName[MAX_PATH];		// MemModule Name (or full file path name)
}MEM_MODULE, *PMEM_MODULE;


//////////////////////////////////////////////////////////////////////////
// public
// 

/*
* function of the MemModuleHelper
*/
typedef enum _MMHELPER_METHOD
{
	MHM_BOOL_LOAD,
	MHM_VOID_FREE,
	MHM_FARPROC_GETPROC,
}MMHELPER_METHOD;

typedef int(__stdcall * Type_MemModuleHelper)(
	PMEM_MODULE, MMHELPER_METHOD, LPCTSTR, LPCSTR, BOOL);

EXTERN_C VOID
mmLoaderSCStart();

EXTERN_C VOID
mmLoaderSCEnd();

/************************************************************************\
 *
 * Auxiliary Function:
 *		use the mmLoader through this function after it is loaded from shell code.
 *
 * Parameters:
 *		pMmeModule:
 *
 *		method:
 *			Function to be used
 *
 *		lpModuleName:
 *			name of the module to be loaded, only valid when method == MHM_BOOL_LOAD
 *			
 *		lpProcName:
 *			name of the proc to be retrieved, only valid when MHM_FARPROC_GETPROC
 *			
 *		bCallEntry:
 *			need to call the module entry point?
 *
 *	return value:
 *		µ±methodÎªMHM_BOOL_LOAD:
 *		when method == MHM_BOOL_LOAD
 *			return the resulT of loading, TRUE or FALSE
 *
 *		when method MHM_VOID_FREE:
 *			no return value
 *
 *		when method == MHM_FARPROC_GETPROC
 *			return the address of the target proc, return NULL when failed to get the address
 *
 *
 *
\************************************************************************/
EXTERN_C int __stdcall
MemModuleHelper(
	_Out_ PMEM_MODULE pMmeModule, 
	_In_ MMHELPER_METHOD method, 
	_In_ LPCTSTR lpModuleName, 
	_In_ LPCSTR lpProcName, 
	_In_ BOOL bCallEntry);

EXTERN_C BOOL __stdcall
LoadMemModule(
	_Out_ PMEM_MODULE pMemModule,
	_In_ LPCTSTR lpName, 
	_In_ BOOL bCallEntry);

EXTERN_C FARPROC __stdcall
GetMemModuleProc(
	_Out_ PMEM_MODULE pMemModule,
	_In_ LPCSTR lpName);

EXTERN_C VOID __stdcall
FreeMemModule(_Out_ PMEM_MODULE pMemModule);

#endif