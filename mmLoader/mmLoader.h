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
// 系统相关的函数指针表
typedef struct __NTFUNCPTRS
{
	LPVOID pfnCreateFileW;			//CreateFileW
	LPVOID pfnGetFileSize;			//GetFileSize
	LPVOID pfnCreateFileMappingW;	//CreateFileMappingW
	LPVOID pfnMapViewOfFile;			//MapViewOfFile
	LPVOID pfnUnmapViewOfFile;		//UnmapViewOfFile
	LPVOID pfnCloseHandle;			//CloseHandle
	LPVOID pfnGetModuleHandleA;		//GetModuleHandleA
	LPVOID pfnLoadLibraryA;			//LoadLibraryA
	LPVOID pfnGetProcAddress;		//GetProcAddress
	LPVOID pfnVirtualAlloc;			//VirtualAlloc
	LPVOID pfnVirtualFree;			//VirtualFree
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
	union							// MemModule base
	{
		DWORD	dwBase;
		HMODULE	hModule;
		LPVOID	lpBase;
		PIMAGE_DOS_HEADER pImageDosHeader;
	};
	DWORD dwSizeOfImage;			// MemModule size
	DWORD dwCrc;					// MemModule crc32

	BOOL	bLoadOk;				// MemModule is load ok?

	PNTFUNCPTRSTABLE pNtFuncptrsTable;	// Pointer to NT function pointers table 

	struct							// Raw file resource data
	{
		HANDLE	h;
		HANDLE	hMapping;
		LPVOID	pBuffer;
	}RawFile;

	TCHAR tszModuleName[MAX_PATH];	// MemModule Name (or full file path name)
}MEM_MODULE, *PMEM_MODULE;



//////////////////////////////////////////////////////////////////////////
// public
// 

/*
 * 用于控制MemModuleHelper的行为
 */ 
typedef enum _MMHELPER_METHOD
{
	MHM_BOOL_LOAD,
	MHM_VOID_FREE,
	MHM_FARPROC_GETPROC,
}MMHELPER_METHOD;


/************************************************************************\
 * 
 * 辅助函数：
 *		当mmLoader被ShellCode化之后对mmLoader的使用都要通过这个函数来实现
 * 参数：
 *		pMmeModule：
 *			
 *		method：
 *			需要调用的功能的类型
 *		
 *		lpModuleName：
 *			需要加载的模块名(只有当method为MHM_BOOL_LOAD时候有效)
 *		lpProcName：
 *			需要获取地址的的Proc的名字(只有当method为MHM_FARPROC_GETPROC时候有效)
 *		
 *		bCallEntry：
 *			是否需要调用模块的入口点函数(只有当method为MHM_BOOL_LOAD时候有效)
 *		
 *	返回值：
 *		当method为MHM_BOOL_LOAD：
 *			返回值为BOOL类型，代表是否Load成功
 *			
 *		当method为MHM_VOID_FREE：
 *			返回值无任何意义
 *		
 *		当method为MHM_FARPROC_GETPROC：
 *			返回值为FARPROC类型，代表获取的目标函数的地址，或者NULL为获取失败
 *		
 * 
 * 
\************************************************************************/

extern unsigned char mmLoaderShellCode[3712];

EXTERN_C VOID
mmLoaderSCStart();

EXTERN_C VOID
mmLoaderSCEnd();

EXTERN_C int __stdcall
MemModuleHelper(PMEM_MODULE pMmeModule, MMHELPER_METHOD method, LPCTSTR lpModuleName, LPCSTR lpProcName, BOOL bCallEntry);

typedef int (__stdcall * Type_MemModuleHelper)(PMEM_MODULE, MMHELPER_METHOD, LPCTSTR, LPCSTR, BOOL);

EXTERN_C BOOL __stdcall
LoadMemModule(PMEM_MODULE pMemModule, LPCTSTR lpName, BOOL bCallEntry);

EXTERN_C FARPROC __stdcall
GetMemModuleProc(PMEM_MODULE pMemModule, LPCSTR lpName); 

EXTERN_C VOID __stdcall
FreeMemModule(PMEM_MODULE pMemModule);

#endif