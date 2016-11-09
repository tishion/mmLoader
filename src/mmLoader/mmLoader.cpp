#include <windows.h>
#include "mmLoader.h"

#pragma region forwardDeclaration

BOOL OpenAndMapView(LPCTSTR pFilePathName, PMEM_MODULE pMemModule);
BOOL IsValidPEFormat(LPVOID pBuffer);
BOOL MapMemModuleSections(PMEM_MODULE pMemModule);
BOOL ReleaseRawFileResource(PMEM_MODULE pMemModule);
BOOL RelocateModuleBase(PMEM_MODULE pMemModule);
BOOL ResolveImportTable(PMEM_MODULE pMemModule);
BOOL SetMemProtectStatus(PMEM_MODULE pMemModule);
BOOL ExecuteTLSCallback(PMEM_MODULE pMemModule);
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);
FARPROC GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName);
VOID UnmapMemModule(PMEM_MODULE pMemModule);

// CRC32 functions
inline unsigned int mml_getcrc32(unsigned int uInit, void* pBuf, unsigned int nBufSize);

// Memory functions
inline int mml_strlenA(const char* psz);
inline int mml_strcmpA(const char* psza, const char* pszb);
inline wchar_t* mml_strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax);
inline void* mml_memset(void* pv, int c, unsigned int cb);
inline void* mml_memmove(void* pvDest, const void* pvSrc, unsigned int cb);

#pragma endregion forwardDeclaration

#pragma region mmLoaderImpl
typedef HANDLE(WINAPI * Type_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI * Type_GetFileSize)(HANDLE, LPDWORD);
typedef HANDLE(WINAPI * Type_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID(WINAPI * Type_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI * Type_UnmapViewOfFile)(LPVOID);
typedef BOOL(WINAPI * Type_CloseHandle)(HANDLE);
typedef LPVOID(WINAPI * Type_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI * Type_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI * Type_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI * Type_GetModuleHandleA)(LPCSTR);
typedef HMODULE(WINAPI * Type_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI * Type_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI * Type_DllMain)(HMODULE, DWORD, LPVOID);

/// <summary>
/// 
/// </summary>
/// <param name="pMmeModule"></param>
/// <param name="method"></param>
/// <param name="lpModuleName"></param>
/// <param name="lpProcName"></param>
/// <param name="bCallEntry"></param>
/// <returns></returns>
LPVOID __stdcall MemModuleHelper(
	PMEM_MODULE pMmeModule, 
	MMHELPER_METHOD method, 
	LPCTSTR lpModuleName, 
	LPCSTR lpProcName, 
	BOOL bCallEntry)
{
	switch (method)
	{
	case MHM_BOOL_LOAD:
		{
			return (LPVOID)(INT_PTR)LoadMemModule(pMmeModule, lpModuleName, bCallEntry);
		}
		break;
	case MHM_VOID_FREE:
		{
			FreeMemModule(pMmeModule);
		}
		break;
	case MHM_FARPROC_GETPROC:
		{
			return (LPVOID)GetMemModuleProc(pMmeModule, lpProcName);
		}
		break;
	default:
		break;
	}

	return 0;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <param name="lpName"></param>
/// <param name="bCallEntry"></param>
/// <returns></returns>
BOOL __stdcall LoadMemModule(PMEM_MODULE pMemModule, LPCTSTR lpName, BOOL bCallEntry)
{
	if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable || NULL == lpName)
		return FALSE;

	// Open file and map memory
	if (FALSE == OpenAndMapView(lpName, pMemModule))
		return FALSE;

	// Verify file format
	if (FALSE == IsValidPEFormat(pMemModule->RawFile.pBuffer))
		return FALSE;

	// Map PE header and section table into memory
	if (FALSE == MapMemModuleSections(pMemModule))
		return FALSE;

	if (FALSE == ReleaseRawFileResource(pMemModule))
		return FALSE;

	// Relocate the module base
	if (FALSE == RelocateModuleBase(pMemModule))
	{
		UnmapMemModule(pMemModule);
		return FALSE;
	}

	// Resolve the import table
	if (FALSE == ResolveImportTable(pMemModule))
	{
		UnmapMemModule(pMemModule);
		return FALSE;
	}

	pMemModule->dwCrc = mml_getcrc32(
		0, pMemModule->lpBase, pMemModule->dwSizeOfImage);
	mml_strcpyW(pMemModule->wszModuleName, lpName, _countof(pMemModule->wszModuleName));

	// Correct the protect flag for all section pages
	if (FALSE == SetMemProtectStatus(pMemModule))
	{
		UnmapMemModule(pMemModule);
		return FALSE;
	}

	if (FALSE == ExecuteTLSCallback(pMemModule))
		return FALSE;

	if (bCallEntry)
	{
		if (FALSE == CallModuleEntry(pMemModule, DLL_PROCESS_ATTACH))
		{
			// failed to call entry point,
			// clean resource, return false
			UnmapMemModule(pMemModule);
			return FALSE;
		}
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
VOID __stdcall FreeMemModule(PMEM_MODULE pMemModule)
{
	if (NULL != pMemModule)
	{
		CallModuleEntry(pMemModule, DLL_PROCESS_DETACH);
		UnmapMemModule(pMemModule);
	}
}

FARPROC __stdcall GetMemModuleProc(PMEM_MODULE pMemModule, LPCSTR lpName)
{
	if (NULL != pMemModule && lpName != NULL)
		return GetExportedProcAddress(pMemModule, lpName);

	return NULL;
}

/// <summary>
/// Tests the return value.
/// </summary>
#define IfFalseGoExit(x) { br=(x); if (!br) goto _Exit; }

/// <summary>
/// Create a pointer value.
/// </summary>
#define MakePointer(t, p, offset) ((t)((PUINT8)(p) + offset))

/// <summary>
/// Opens and maps the view of the disk file.
/// </summary>
/// <param name="pFilePathName"></param>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL OpenAndMapView(LPCTSTR pFilePathName, PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable)
		return FALSE;

	Type_CreateFileW pfnCreateFileW = (Type_CreateFileW)(pMemModule->pNtFuncptrsTable->pfnCreateFileW);
	Type_GetFileSize pfnGetFileSize = (Type_GetFileSize)(pMemModule->pNtFuncptrsTable->pfnGetFileSize);
	Type_CreateFileMappingW pfnCreateFileMappingW = (Type_CreateFileMappingW)(pMemModule->pNtFuncptrsTable->pfnCreateFileMappingW);
	Type_MapViewOfFile pfnMapViewOfFile = (Type_MapViewOfFile)(pMemModule->pNtFuncptrsTable->pfnMapViewOfFile);

	BOOL br = FALSE;
	pMemModule->RawFile.h = pfnCreateFileW(pFilePathName, GENERIC_READ, FILE_SHARE_READ, 
		NULL, OPEN_EXISTING, NULL, NULL);
	IfFalseGoExit(INVALID_HANDLE_VALUE != pMemModule->RawFile.h);
	IfFalseGoExit(NULL != pMemModule->RawFile.h);

	// Check file size
	DWORD dwFileSize = pfnGetFileSize(pMemModule->RawFile.h, NULL);
	IfFalseGoExit(INVALID_FILE_SIZE != dwFileSize);

	// If file size is less than DOS header, invalid file.
	IfFalseGoExit(dwFileSize > (sizeof(IMAGE_DOS_HEADER)));

	pMemModule->RawFile.hMapping = pfnCreateFileMappingW(pMemModule->RawFile.h, 0, PAGE_READONLY, 0, 0, NULL);
	IfFalseGoExit(NULL != pMemModule->RawFile.hMapping);

	pMemModule->RawFile.pBuffer = pfnMapViewOfFile(pMemModule->RawFile.hMapping, FILE_MAP_READ, 0, 0, 0);
	IfFalseGoExit(NULL != pMemModule->RawFile.pBuffer);

_Exit:
	return br;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL ReleaseRawFileResource(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable)
		return FALSE;

	Type_UnmapViewOfFile pfnUnmapViewOfFile = (Type_UnmapViewOfFile)(pMemModule->pNtFuncptrsTable->pfnUnmapViewOfFile);
	Type_CloseHandle pfnCloseHandle = (Type_CloseHandle)(pMemModule->pNtFuncptrsTable->pfnCloseHandle);

	if (pMemModule->RawFile.pBuffer)
	{
		pfnUnmapViewOfFile(pMemModule->RawFile.pBuffer);
		pMemModule->RawFile.pBuffer = NULL;
	}

	if (pMemModule->RawFile.hMapping)
	{
		pfnCloseHandle(pMemModule->RawFile.hMapping);
		pMemModule->RawFile.hMapping = NULL;
	}

	if (pMemModule->RawFile.h)
	{
		pfnCloseHandle(pMemModule->RawFile.h);
		pMemModule->RawFile.h = INVALID_HANDLE_VALUE;
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pBuffer"></param>
/// <returns></returns>
BOOL IsValidPEFormat(LPVOID pBuffer)
{
	if (NULL == pBuffer)
		return FALSE;

	BOOL br = FALSE;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	// Check the MZ signature
	IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

	// Check PE signature
	PIMAGE_NT_HEADERS pImageNtHeader =
		MakePointer(PIMAGE_NT_HEADERS, pBuffer, pImageDosHeader->e_lfanew);
	IfFalseGoExit(IMAGE_NT_SIGNATURE == pImageNtHeader->Signature);

#ifdef _WIN64
	if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine)
	{
		IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader->OptionalHeader.Magic);
	}
#else
	if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine)
	{
		IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);
	}
#endif
	else
		IfFalseGoExit(FALSE);

_Exit:
	return br;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL MapMemModuleSections(PMEM_MODULE pMemModule)
{
	// Validate
	if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable || NULL == pMemModule->RawFile.pBuffer)
		return FALSE;

	// Function pointer
	Type_VirtualAlloc pfnVirtualAlloc = (Type_VirtualAlloc)(pMemModule->pNtFuncptrsTable->pfnVirtualAlloc);
	Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pNtFuncptrsTable->pfnVirtualFree);

	// Convert to IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->RawFile.pBuffer);

	// Get the pointer to IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
	
	int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	
	PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
		PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	DWORD dwImageSizeLimit = 0;
	// Find last section limit
	for (int i = 0; i < nNumberOfSections; ++i)
	{
		if (0 != pImageSectionHeader[i].VirtualAddress)
		{
			if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
				dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
		}
	}

	dwImageSizeLimit = (dwImageSizeLimit + pMemModule->dwPageSize - 1) & ~(pMemModule->dwPageSize - 1);

	// Reserve virtual memory 
	LPVOID lpBase = pfnVirtualAlloc(
		(LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), 
		dwImageSizeLimit,
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_READWRITE);

	// Failed to reserve space at ImageBase, then it's up to the system
	if (NULL == lpBase)
	{
		// Reserver memory in arbitrary address
		lpBase = pfnVirtualAlloc(
			NULL, 
			dwImageSizeLimit,
			MEM_RESERVE | MEM_COMMIT, 
			PAGE_READWRITE);

		// Failed again, return 
		if (NULL == lpBase) return FALSE;
	}

	// Commit memory for PE header
	LPVOID pDest = pfnVirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	if (!pDest) return FALSE;
	mml_memmove(pDest, pMemModule->RawFile.pBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);
	// store the base address of this module.
	pMemModule->lpBase = pDest;
	pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
	pMemModule->bLoadOk = TRUE;

	pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
	pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
	pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	LPVOID pSectionBase = NULL;
	LPVOID pSectionDataSource = NULL;

	for (int i = 0; i < nNumberOfSections; ++i)
	{
		if (0 != pImageSectionHeader[i].VirtualAddress)
		{
			pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

			if (0 == pImageSectionHeader[i].SizeOfRawData)
			{
				if (pImageNtHeader->OptionalHeader.SectionAlignment > 0)
				{
					pDest = pfnVirtualAlloc(pSectionBase, pImageNtHeader->OptionalHeader.SectionAlignment,
						MEM_COMMIT, PAGE_READWRITE);
					if (NULL == pDest) return FALSE;

					// Always use position from file to support alignments smaller than page size.
					mml_memset(pSectionBase, 0, pImageNtHeader->OptionalHeader.SectionAlignment);
				}
			}
			else
			{
				// Commit this section to target address
				pDest = pfnVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
				if (NULL == pDest) return FALSE;
				pSectionDataSource = MakePointer(LPVOID, pMemModule->RawFile.pBuffer, pImageSectionHeader[i].PointerToRawData);
				mml_memmove(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
			}

			pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
		}
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL RelocateModuleBase(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule  || NULL == pMemModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS,
		pMemModule->pImageDosHeader, 
		pMemModule->pImageDosHeader->e_lfanew);

	// Get the delta of the real image base with the predefined
	LONGLONG lBaseDelta = ((PUINT8)pMemModule->iBase - (PUINT8)pImageNtHeader->OptionalHeader.ImageBase);

	// This module has been loaded to the ImageBase, no need to do relocation
	if (0 == lBaseDelta) return TRUE;

	if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
		|| 0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return TRUE;

	PIMAGE_BASE_RELOCATION pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pMemModule->lpBase, 
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (NULL == pImageBaseRelocation) return FALSE;

	while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock))
	{
		PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

		int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < NumberOfRelocationData; i++)
		{
			if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12))
			{
				PDWORD pAddress = (PDWORD)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
				*pAddress += (DWORD)lBaseDelta;
			}

#ifdef _WIN64
			if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12))
			{
				PULONGLONG pAddress = (PULONGLONG)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
				*pAddress += lBaseDelta;
			}
#endif
		}

		pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL ResolveImportTable(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule  || NULL == pMemModule->pNtFuncptrsTable || NULL == pMemModule->pImageDosHeader)
		return FALSE;

	Type_GetModuleHandleA pfnGetModuleHandleA = (Type_GetModuleHandleA)(pMemModule->pNtFuncptrsTable->pfnGetModuleHandleA);
	Type_LoadLibraryA pfnLoadLibraryA = (Type_LoadLibraryA)(pMemModule->pNtFuncptrsTable->pfnLoadLibraryA);
	Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)(pMemModule->pNtFuncptrsTable->pfnGetProcAddress);

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
		|| pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return TRUE;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pMemModule->lpBase, 
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
	{
		// Get the dependent module name
		PCHAR pDllName = MakePointer(PCHAR, pMemModule->lpBase, pImageImportDescriptor->Name);

		// Get the dependent module handle
		HMODULE hMod = pfnGetModuleHandleA(pDllName);

		// Load the dependent module
		if (NULL == hMod) hMod = pfnLoadLibraryA(pDllName);

		// Failed
		if (NULL == hMod) return FALSE;

		// Original thunk
		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDescriptor->OriginalFirstThunk)
			pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->OriginalFirstThunk);
		else
			pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);

		// IAT thunk
		PIMAGE_THUNK_DATA pIATThunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, 
			pImageImportDescriptor->FirstThunk);

		for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++)
		{
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
			{
				lpFunction = pfnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImageImportByName = MakePointer(
					PIMAGE_IMPORT_BY_NAME, pMemModule->lpBase, pOriginalThunk->u1.AddressOfData);

				lpFunction = pfnGetProcAddress(hMod, (LPCSTR)&(pImageImportByName->Name));
			}

			// Write into IAT
#ifdef _WIN64
			pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
			pIATThunk->u1.Function = (DWORD)lpFunction;
#endif
		}
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL SetMemProtectStatus(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable)
		return FALSE;

	int ProtectionMatrix[2][2][2] = {
		{
			// not executable
			{ PAGE_NOACCESS, PAGE_WRITECOPY },
			{ PAGE_READONLY, PAGE_READWRITE },
		},
		{
			// executable
			{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
			{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
		},
	};

	Type_VirtualProtect pfnVirtualProtect = (Type_VirtualProtect)(pMemModule->pNtFuncptrsTable->pfnVirtualProtect);
	Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pNtFuncptrsTable->pfnVirtualFree);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->lpBase);

	ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
	ulBaseHigh = (pMemModule->iBase & 0xffffffff00000000);
#endif

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

	int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
		PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++)
	{
		DWORD protectFlag = 0;
		DWORD oldProtect = 0;
		BOOL isExecutable = FALSE;
		BOOL isReadable = FALSE;
		BOOL isWritable = FALSE;

		BOOL isNotCache = FALSE;
		ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
		DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
		if (0 == dwSecionSize) continue;

		// This section is in this page
		DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

		// Discardable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			if (!pfnVirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT))
				return FALSE;
			continue;
		}

		// Executable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			isExecutable = TRUE;

		// Readable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
			isReadable = TRUE;

		// Writable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			isWritable = TRUE;

		if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
			isNotCache = TRUE;

		protectFlag = ProtectionMatrix[isExecutable][isReadable][isWritable];
		if (isNotCache) protectFlag |= PAGE_NOCACHE;
		if (!pfnVirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect))
			return FALSE;
	}

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
BOOL ExecuteTLSCallback(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS,
		pMemModule->pImageDosHeader,
		pMemModule->pImageDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (imageDirectoryEntryTls.VirtualAddress == 0)	return TRUE;

	PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pMemModule->iBase + imageDirectoryEntryTls.VirtualAddress);
	PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
	if (callback)
	{
		while (*callback)
		{
			(*callback)((LPVOID)pMemModule->hModule, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
	}
	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <param name="dwReason"></param>
/// <returns></returns>
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason)
{
	if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS,
		pMemModule->pImageDosHeader, 
		pMemModule->pImageDosHeader->e_lfanew);

	Type_DllMain pfnModuleEntry = NULL;

	pfnModuleEntry = MakePointer(
		Type_DllMain, 
		pMemModule->lpBase, 
		pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

	if (NULL == pfnModuleEntry)
		return FALSE;

	return pfnModuleEntry(pMemModule->hModule, dwReason, NULL);
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <param name="lpName"></param>
/// <returns></returns>
FARPROC GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName)
{
	if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
		return NULL;

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
		PIMAGE_NT_HEADERS,
		pMemModule->pImageDosHeader, 
		pMemModule->pImageDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = MakePointer(
		PIMAGE_EXPORT_DIRECTORY, 
		pMemModule->lpBase, 
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pAddressOfNames = MakePointer(
		PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNames);

	PWORD pAddressOfNameOrdinals = MakePointer(
		PWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNameOrdinals);

	PDWORD pAddressOfFunctions = MakePointer(
		PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfFunctions);

	int nNumberOfFunctions = pImageExportDirectory->NumberOfFunctions;
	for (int i = 0; i < nNumberOfFunctions; ++i)
	{
		DWORD dwAddressOfName = pAddressOfNames[i];

		LPCSTR pFunctionName = MakePointer(
			LPCSTR, pMemModule->lpBase, dwAddressOfName);

		if (0 == mml_strcmpA(lpName, pFunctionName))
		{
			WORD wOrdinal = pAddressOfNameOrdinals[i];
			DWORD dwFunctionOffset = pAddressOfFunctions[wOrdinal];
			FARPROC pfnTargetProc = MakePointer(
				FARPROC, pMemModule->lpBase, dwFunctionOffset);

			return pfnTargetProc;
		}
	}

	return NULL;
}

/// <summary>
/// 
/// </summary>
/// <param name="pMemModule"></param>
/// <returns></returns>
VOID UnmapMemModule(PMEM_MODULE pMemModule)
{
	if (NULL == pMemModule
		|| NULL == pMemModule->pNtFuncptrsTable
		|| FALSE == pMemModule->bLoadOk
		|| NULL == pMemModule->lpBase)
		return;

	Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pNtFuncptrsTable->pfnVirtualFree);

	pfnVirtualFree(pMemModule->lpBase, 0, MEM_RELEASE);

	pMemModule->lpBase = NULL;
	pMemModule->dwCrc = 0;
	pMemModule->dwSizeOfImage = 0;
	pMemModule->bLoadOk = FALSE;

	mml_memset(pMemModule->wszModuleName, 0, sizeof(pMemModule->wszModuleName));
}

//
#include "strmem.h"

//
#include "crc.h"

/// <summary>
/// 
/// </summary>
inline void MMLOADERSHELLCODEEND()
{
	MemModuleHelper(0, (MMHELPER_METHOD)0, 0, 0, 0);
}

#pragma endregion mmLoaderImpl