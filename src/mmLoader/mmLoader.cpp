#include <windows.h>
#include "mmLoader.h"

#pragma region forwardDeclaration

BOOL IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);
BOOL MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);
BOOL RelocateModuleBase(PMEM_MODULE pMemModule);
BOOL ResolveImportTable(PMEM_MODULE pMemModule);
BOOL SetMemProtectStatus(PMEM_MODULE pMemModule);
BOOL ExecuteTLSCallback(PMEM_MODULE pMemModule);
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);
FARPROC GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName);
VOID UnmapMemModule(PMEM_MODULE pMemModule);

// CRC32 functions
unsigned int mml_getcrc32(unsigned int uInit, void* pBuf, unsigned int nBufSize);

// Memory functions
int mml_strlenA(const char* psz);
int mml_strcmpA(const char* psza, const char* pszb);
wchar_t* mml_strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax);
void* mml_memset(void* pv, int c, unsigned int cb);
void* mml_memmove(void* pvDest, const void* pvSrc, unsigned int cb);
void mmLoaderCodeEnd();

#pragma endregion forwardDeclaration

#pragma region mmLoaderImpl
typedef LPVOID(WINAPI * Type_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI * Type_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI * Type_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI * Type_GetModuleHandleA)(LPCSTR);
typedef HMODULE(WINAPI * Type_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI * Type_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI * Type_DllMain)(HMODULE, DWORD, LPVOID);

LPVOID __stdcall MemModuleHelper(
    PMEM_MODULE pMmeModule, 
    MMHELPER_METHOD method, 
    LPVOID lpPeModuleBuffer,
    LPCSTR lpProcName,
    BOOL bCallEntry)
{
    switch (method)
    {
    case MHM_BOOL_LOAD:
        {
            return (LPVOID)(INT_PTR)LoadMemModule(pMmeModule, lpPeModuleBuffer, bCallEntry);
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

BOOL __stdcall LoadMemModule(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry)
{
    if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable || NULL == lpPeModuleBuffer)
        return FALSE;

    pMemModule->dwErrorCode = ERROR_SUCCESS;

    // Verify file format
    if (FALSE == IsValidPEFormat(pMemModule, lpPeModuleBuffer))
    {
        return FALSE;
    }

    // Map PE header and section table into memory
    if (FALSE == MapMemModuleSections(pMemModule, lpPeModuleBuffer))
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

VOID __stdcall FreeMemModule(PMEM_MODULE pMemModule)
{
    if (NULL != pMemModule)
    {
        // Free the module
        pMemModule->dwErrorCode = ERROR_SUCCESS;
        CallModuleEntry(pMemModule, DLL_PROCESS_DETACH);
        UnmapMemModule(pMemModule);
    }
}

FARPROC __stdcall GetMemModuleProc(PMEM_MODULE pMemModule, LPCSTR lpName)
{
    if (NULL != pMemModule && lpName != NULL)
    {
        // Get the address of the specific function
        pMemModule->dwErrorCode = ERROR_SUCCESS;
        return GetExportedProcAddress(pMemModule, lpName);
    }

    return NULL;
}

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExitWithError(x, exp) do { if (!(br = (x)) && (exp)) goto _Exit; } while (0)

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExit(x) do { if (!(br = (x))) goto _Exit; } while (0)

/// <summary>
/// Create a pointer value.
/// </summary>
#define MakePointer(t, p, offset) ((t)((PUINT8)(p) + offset))

/// <summary>
/// Verifies the format of the buffer content.
/// </summary>
/// <param name="pBuffer">The buffer containing the file data.</param>
/// <returns>True if the data is valid PE format.</returns>
BOOL IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer)
{
    // Validate the parameters
    if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable)
        return FALSE;

    // Initialize the return value
    BOOL br = FALSE;

    // Get the DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpPeModuleBuffer;

    // Check the MZ signature
    IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

    // Check PE signature
    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, lpPeModuleBuffer, pImageDosHeader->e_lfanew);
    IfFalseGoExit(IMAGE_NT_SIGNATURE == pImageNtHeader->Signature);

#ifdef _WIN64
    // Check the machine type
    if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine)
    {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#else
    // Check the machine type
    if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine)
    {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#endif
    else
        br = FALSE;

_Exit:
    // If this is invalid PE file data return error
    if (!br) pMemModule->dwErrorCode = MMEC_BAD_PE_FORMAT;
    return br;
}

/// <summary>
/// Maps all the sections.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer)
{
    // Validate
    if (NULL == pMemModule || NULL == pMemModule->pNtFuncptrsTable || NULL == lpPeModuleBuffer)
        return FALSE;

    // Function pointer
    Type_VirtualAlloc pfnVirtualAlloc = (Type_VirtualAlloc)(pMemModule->pNtFuncptrsTable->pfnVirtualAlloc);
    Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pNtFuncptrsTable->pfnVirtualFree);

    // Convert to IMAGE_DOS_HEADER
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpPeModuleBuffer);

    // Get the pointer to IMAGE_NT_HEADERS
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(
        PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    
    // Get the section count
    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
    
    // Get the section header
    PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
        PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    // Find the last section limit
    DWORD dwImageSizeLimit = 0;
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        if (0 != pImageSectionHeader[i].VirtualAddress)
        {
            if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
                dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
        }
    }

    // Align the last image size limit to the page size
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
        if (NULL == lpBase)
        {
            pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
            return FALSE;
        }
    }

    // Commit memory for PE header
    LPVOID pDest = pfnVirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
    if (!pDest)
    {
        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
        return FALSE;
    }
    
    // Copy the data of PE header to the memory allocated
    mml_memmove(pDest, lpPeModuleBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);

    // Store the base address of this module.
    pMemModule->lpBase = pDest;
    pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
    pMemModule->bLoadOk = TRUE;

    // Get the DOS header, NT header and Section header from the new PE header buffer
    pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
    pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    // Map all section data into the memory
    LPVOID pSectionBase = NULL;
    LPVOID pSectionDataSource = NULL;
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        if (0 != pImageSectionHeader[i].VirtualAddress)
        {
            // Get the section base
            pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

            if (0 == pImageSectionHeader[i].SizeOfRawData)
            {
                if (pImageNtHeader->OptionalHeader.SectionAlignment > 0)
                {
                    // If the size is zero, but the section alignment is not zero then allocate memory with the aligment
                    pDest = pfnVirtualAlloc(pSectionBase, pImageNtHeader->OptionalHeader.SectionAlignment,
                        MEM_COMMIT, PAGE_READWRITE);
                    if (NULL == pDest)
                    {
                        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                        return FALSE;
                    }

                    // Always use position from file to support alignments smaller than page size.
                    mml_memset(pSectionBase, 0, pImageNtHeader->OptionalHeader.SectionAlignment);
                }
            }
            else
            {
                // Commit this section to target address
                pDest = pfnVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
                if (NULL == pDest)
                {
                    pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                    return FALSE;
                }

                // Get the section data source and copy the data to the section buffer
                pSectionDataSource = MakePointer(LPVOID, lpPeModuleBuffer, pImageSectionHeader[i].PointerToRawData);
                mml_memmove(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
            }

            // Get next section header
            pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
        }
    }

    return TRUE;
}

/// <summary>
/// Relocates the module.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL RelocateModuleBase(PMEM_MODULE pMemModule)
{
    // Validate the parameters
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

    if (NULL == pImageBaseRelocation)
    {
        pMemModule->dwErrorCode = MMEC_INVALID_RELOCATION_BASE;
        return FALSE;
    }

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
/// Resolves the import table.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
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
        if (NULL == hMod)
        {
            pMemModule->dwErrorCode = MMEC_IMPORT_MODULE_FAILED;
            return FALSE;
        }
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
/// Sets the memory protected stats of all the sections.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
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
            pfnVirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT);
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
        {
            pMemModule->dwErrorCode = MMEC_PROTECT_SECTION_FAILED;
            return FALSE;
        }
    }

    return TRUE;
}

/// <summary>
/// Executes the TLS callback function.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
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
/// Calls the module entry.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="dwReason">The reason of the calling.</param>
/// <returns>True if successful.</returns>
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
    {
        pMemModule->dwErrorCode = MMEC_INVALID_ENTRY_POINT;
        return FALSE;
    }

    return pfnModuleEntry(pMemModule->hModule, dwReason, NULL);
}

/// <summary>
/// Gets the exported function address.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="lpName">The function name.</param>
/// <returns>The address of the function or null.</returns>
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
/// Unmaps all the sections.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
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
}

//
#include "strmem.h"

//
#include "crc.h"

/// <summary>
/// Mark.
/// </summary>
void mmLoaderCodeEnd()
{
    return;
}

#pragma endregion mmLoaderImpl