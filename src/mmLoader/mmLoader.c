#include <windows.h>

#include "mmLoader.h"

#pragma region forwardDeclaration
typedef FARPROC(WINAPI *Type_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *Type_GetModuleHandleA)(LPCSTR);
typedef HMODULE(WINAPI *Type_LoadLibraryA)(LPCSTR);
typedef LPVOID(WINAPI *Type_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *Type_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI *Type_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HGLOBAL(WINAPI *Type_GlobalAlloc)(_In_ UINT, _In_ SIZE_T);
typedef HGLOBAL(WINAPI *Type_GlobalFree)(_In_ HGLOBAL);
typedef BOOL(WINAPI *Type_DllMain)(HMODULE, DWORD, LPVOID);

/// <summary>
/// Function table. These function will be used in the mmLoader.
/// </summary>
typedef struct API_PTR_TABLE {
  LPVOID pfnGetProcAddress;   // GetProcAddress
  LPVOID pfnGetModuleHandleA; // GetModuleHandleA
  LPVOID pfnLoadLibraryA;     // LoadLibraryA

  LPVOID pfnVirtualAlloc;   // VirtualAlloc
  LPVOID pfnVirtualFree;    // VirtualFree
  LPVOID pfnVirtualProtect; // VirtualProtect

  LPVOID pfnGlobalAlloc;
  LPVOID pfnGlobalFree;
} APIPTR_TABLE, *PAPIPTR_TABLE;

/// <summary>
/// Represents the memory module instance.
/// </summary>
typedef struct __MEMMODULE_S {
  union {
#if _WIN64
    ULONGLONG iBase;
#else
    DWORD iBase;
#endif
    HMODULE hModule;
    LPVOID lpBase;
    PIMAGE_DOS_HEADER pImageDosHeader;
  };                   // MemModule base
  DWORD dwSizeOfImage; // MemModule size
  DWORD dwCrc;         // MemModule crc32

  PAPIPTR_TABLE pApis; // Pointer to parameters
  BOOL bCallEntry;     // Call module entry
  BOOL bLoadOk;        // MemModule is loaded ok?
  DWORD dwErrorCode;   // Last error code
} MEM_MODULE, *PMEM_MODULE;

BOOL
LoadMemModuleInternal(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry);

FARPROC
GetMemModuleProcInternal(PMEM_MODULE pMemModule, LPCSTR lpName);

VOID
FreeMemModuleInternal(PMEM_MODULE pMemModule);

FARPROC
_GetProcAddress(HMODULE hModule, LPCSTR lpName);

HMODULE
_GetModuleHandle(LPCWSTR lpName);

PAPIPTR_TABLE
InitApiTable();

BOOL
IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);

BOOL
MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);

BOOL
RelocateModuleBase(PMEM_MODULE pMemModule);

BOOL
ResolveImportTable(PMEM_MODULE pMemModule);

BOOL
SetMemProtectStatus(PMEM_MODULE pMemModule);

BOOL
ExecuteTLSCallback(PMEM_MODULE pMemModule);

BOOL
CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);

FARPROC
GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName);

VOID
UnmapMemModule(PMEM_MODULE pMemModule);

UINT32
GetCRC32(UINT32 uInit, void *pBuf, UINT32 nBufSize);

// Memory functions
int
mml_strlenA(const char *psz);

int
mml_strcmpA(const char *psza, const char *pszb);

int
mml_stricmpW(const wchar_t *pwsza, const wchar_t *pwszb);

wchar_t *
mml_strcpyW(wchar_t *pszDest, const wchar_t *pszSrc, unsigned int nMax);

void *
mml_memset(void *pv, int c, unsigned int cb);

void *
mml_memmove(void *pvDest, const void *pvSrc, unsigned int cb);

#pragma endregion forwardDeclaration

#pragma region mmLoaderImpl

LPVOID
MemModuleHelper(_In_ MMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3) {
  switch (method) {
  case MHM_BOOL_LOAD: {
    return (LPVOID)(INT_PTR)LoadMemModule(lpArg1, (BOOL)(lpArg2 != 0), (DWORD *)lpArg3);
  } break;
  case MHM_VOID_FREE: {
    FreeMemModule(lpArg1);
  } break;
  case MHM_FARPROC_GETPROC: {
    return (LPVOID)GetMemModuleProc(lpArg1, lpArg2);
  } break;
  default:
    break;
  }

  return 0;
}

BOOL
LoadMemModuleInternal(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry) {
  if (NULL == pMemModule || NULL == pMemModule->pApis || NULL == lpPeModuleBuffer)
    return FALSE;

  pMemModule->dwErrorCode = ERROR_SUCCESS;

  // Verify file format
  if (FALSE == IsValidPEFormat(pMemModule, lpPeModuleBuffer)) {
    return FALSE;
  }

  // Map PE header and section table into memory
  if (FALSE == MapMemModuleSections(pMemModule, lpPeModuleBuffer))
    return FALSE;

  // Relocate the module base
  if (FALSE == RelocateModuleBase(pMemModule)) {
    UnmapMemModule(pMemModule);
    return FALSE;
  }

  // Resolve the import table
  if (FALSE == ResolveImportTable(pMemModule)) {
    UnmapMemModule(pMemModule);
    return FALSE;
  }

  pMemModule->dwCrc = GetCRC32(0, pMemModule->lpBase, pMemModule->dwSizeOfImage);

  // Correct the protect flag for all section pages
  if (FALSE == SetMemProtectStatus(pMemModule)) {
    UnmapMemModule(pMemModule);
    return FALSE;
  }

  if (FALSE == ExecuteTLSCallback(pMemModule))
    return FALSE;

  if (bCallEntry) {
    if (FALSE == CallModuleEntry(pMemModule, DLL_PROCESS_ATTACH)) {
      // failed to call entry point,
      // clean resource, return false
      UnmapMemModule(pMemModule);
      return FALSE;
    }
  }

  return TRUE;
}

HMEMMODULE
LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD *pdwError) {
  PAPIPTR_TABLE pApis = InitApiTable();
  if (!pApis) {
    if (pdwError)
      *pdwError = MMEC_INVALID_WIN32_ENV;
    return NULL;
  }

  Type_GlobalAlloc pfnGlobalAlloc = pApis->pfnGlobalAlloc;
  PMEM_MODULE pMemModule = pfnGlobalAlloc(GPTR, sizeof(MEM_MODULE));
  if (!pMemModule) {
    if (pdwError)
      *pdwError = MMEC_INVALID_WIN32_ENV;
    return NULL;
  }

  pMemModule->pApis = pApis;
  pMemModule->bCallEntry = bCallEntry;
  pMemModule->bLoadOk = FALSE;
  pMemModule->dwErrorCode = MMEC_OK;

  if (LoadMemModuleInternal(pMemModule, lpPeModuleBuffer, bCallEntry)) {
    if (pdwError)
      *pdwError = 0;
    return (HMEMMODULE)pMemModule;
  }

  if (pdwError)
    *pdwError = pMemModule->dwErrorCode;
  Type_GlobalFree pfnGlobalFree = pApis->pfnGlobalFree;
  pfnGlobalFree(pMemModule);
  pfnGlobalFree(pApis);
  return NULL;
}

VOID
FreeMemModuleInternal(PMEM_MODULE pMemModule) {
  if (NULL != pMemModule) {
    pMemModule->dwErrorCode = ERROR_SUCCESS;

    if (pMemModule->bCallEntry)
      CallModuleEntry(pMemModule, DLL_PROCESS_DETACH);

    UnmapMemModule(pMemModule);
  }
}

VOID
FreeMemModule(_In_ HMEMMODULE MemModuleHandle) {
  PMEM_MODULE pMemModule = (PMEM_MODULE)MemModuleHandle;
  FreeMemModuleInternal(pMemModule);
  if (pMemModule) {
    Type_GlobalFree pfnGlobalFree = pMemModule->pApis->pfnGlobalFree;
    if (pfnGlobalFree) {
      pfnGlobalFree(pMemModule->pApis);
      pfnGlobalFree(pMemModule);
    }
  }
}

FARPROC
GetMemModuleProcInternal(PMEM_MODULE pMemModule, LPCSTR lpName) {
  if (NULL != pMemModule && lpName != NULL) {
    // Get the address of the specific function
    pMemModule->dwErrorCode = ERROR_SUCCESS;
    return GetExportedProcAddress(pMemModule, lpName);
  }

  return NULL;
}

FARPROC
GetMemModuleProc(_In_ HMEMMODULE MemModuleHandle, _In_ LPCSTR lpName) {
  return GetMemModuleProcInternal((PMEM_MODULE)MemModuleHandle, lpName);
}

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExitWithError(x, exp)                                                                                 \
  do {                                                                                                                 \
    if (!(br = (x)) && (exp))                                                                                          \
      goto _Exit;                                                                                                      \
  } while (0)

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExit(x)                                                                                               \
  do {                                                                                                                 \
    if (!(br = (x)))                                                                                                   \
      goto _Exit;                                                                                                      \
  } while (0)

/// <summary>
/// Create a pointer value.
/// </summary>
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

FARPROC
_GetProcAddress(HMODULE hModule, LPCSTR lpName) {
  if (!hModule || !lpName)
    return NULL;

  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
  if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
  if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
      MakePointer(PIMAGE_EXPORT_DIRECTORY, hModule,
                  pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

  for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
    if (!mml_strcmpA(lpName, (char *)hModule + pNameTable[i])) {
      PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
      PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
      DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
      return MakePointer(PVOID, hModule, dwAddressOffset);
    }
  }

  return NULL;
}

HMODULE
_GetModuleHandle(LPCWSTR lpName) {
  typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
  } UNICODE_STRING;
  typedef UNICODE_STRING *PUNICODE_STRING;
  typedef const UNICODE_STRING *PCUNICODE_STRING;

  typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
  } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

  typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
  } PEB_LDR_DATA, *PPEB_LDR_DATA;

#ifdef _WIN64
  typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
  } PEB, *PPEB;
#else
  typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    LPVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    LPVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
  } PEB, *PPEB;
#endif

  // Get the base address of PEB struct
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  if (pPeb && pPeb->Ldr) {
    // Get pointer value of PEB_LDR_DATA
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // And get header of the InLoadOrderModuleList
    PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
    if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) {
      PLDR_DATA_TABLE_ENTRY pEntry = NULL;
      PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;

      // Find Entry of the fake module
      do {
        pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        // OK, got it
        if (0 == mml_stricmpW(pEntry->BaseDllName.Buffer, lpName)) {
          return pEntry->BaseAddress;
          break;
        }
        pEntry = NULL;
        pCur = pCur->Flink;
      } while (pCur != pHeaderOfModuleList);
    }
  }

  return NULL;
}

PAPIPTR_TABLE
InitApiTable() {
  wchar_t wszKernel[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};
  HMODULE hKernelModule = _GetModuleHandle(wszKernel);
  if (!hKernelModule)
    return NULL;

  char szGetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0};
  Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)_GetProcAddress(hKernelModule, szGetProcAddress);
  if (!pfnGetProcAddress)
    pfnGetProcAddress = (Type_GetProcAddress)_GetProcAddress;

  char szGlobalAlloc[] = {'G', 'l', 'o', 'b', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
  char szGlobalFree[] = {'G', 'l', 'o', 'b', 'a', 'l', 'F', 'r', 'e', 'e', 0};
  Type_GlobalAlloc pfnGlobalAlloc = (Type_GlobalAlloc)_GetProcAddress(hKernelModule, szGlobalAlloc);
  Type_GlobalFree pfnGlobalFree = (Type_GlobalFree)_GetProcAddress(hKernelModule, szGlobalFree);
  if (!pfnGlobalAlloc || !pfnGlobalFree)
    return NULL;

  PAPIPTR_TABLE pApis = pfnGlobalAlloc(GPTR, sizeof(APIPTR_TABLE));
  if (!pApis)
    return NULL;

  pApis->pfnGetProcAddress = pfnGetProcAddress;
  pApis->pfnGlobalAlloc = pfnGlobalAlloc;
  pApis->pfnGlobalFree = pfnGlobalFree;

  do {
    char szGetModuleHandleA[] = {'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0};
    pApis->pfnGetModuleHandleA = pfnGetProcAddress(hKernelModule, szGetModuleHandleA);
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    pApis->pfnLoadLibraryA = pfnGetProcAddress(hKernelModule, szLoadLibraryA);
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualAlloc[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
    pApis->pfnVirtualAlloc = pfnGetProcAddress(hKernelModule, szVirtualAlloc);
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualFree[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0};
    pApis->pfnVirtualFree = pfnGetProcAddress(hKernelModule, szVirtualFree);
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualProtect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};
    pApis->pfnVirtualProtect = pfnGetProcAddress(hKernelModule, szVirtualProtect);
    if (!pApis->pfnGetModuleHandleA)
      break;

    return pApis;
  } while (0);

  return NULL;
}

/// <summary>
/// Verifies the format of the buffer content.
/// </summary>
/// <param name="pBuffer">The buffer containing the file data.</param>
/// <returns>True if the data is valid PE format.</returns>
BOOL
IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer) {
  // Validate the parameters
  if (NULL == pMemModule || NULL == pMemModule->pApis)
    return FALSE;

  // Initialize the return value
  BOOL br = FALSE;

  // Get the DOS header
  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpPeModuleBuffer;

  // Check the MZ signature
  IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

  // Check PE signature
  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, lpPeModuleBuffer, pImageDosHeader->e_lfanew);
  IfFalseGoExit(IMAGE_NT_SIGNATURE == pImageNtHeader->Signature);

#ifdef _WIN64
  // Check the machine type
  if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine) {
    IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader->OptionalHeader.Magic);
  }
#else
  // Check the machine type
  if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine) {
    IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);
  }
#endif
  else
    br = FALSE;

_Exit:
  // If this is invalid PE file data return error
  if (!br)
    pMemModule->dwErrorCode = MMEC_BAD_PE_FORMAT;
  return br;
}

/// <summary>
/// Maps all the sections.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL
MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer) {
  // Validate
  if (NULL == pMemModule || NULL == pMemModule->pApis || NULL == lpPeModuleBuffer)
    return FALSE;

  // Function pointer
  Type_VirtualAlloc pfnVirtualAlloc = (Type_VirtualAlloc)(pMemModule->pApis->pfnVirtualAlloc);
  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfnVirtualFree);

  // Convert to IMAGE_DOS_HEADER
  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpPeModuleBuffer);

  // Get the pointer to IMAGE_NT_HEADERS
  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

  // Get the section count
  int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;

  // Get the section header
  PIMAGE_SECTION_HEADER pImageSectionHeader =
      MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  // Find the last section limit
  DWORD dwImageSizeLimit = 0;
  for (int i = 0; i < nNumberOfSections; ++i) {
    if (0 != pImageSectionHeader[i].VirtualAddress) {
      if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
        dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
    }
  }

  // Remove. The VirtualAlloc will do this for use
  // Align the last image size limit to the page size
  // dwImageSizeLimit = dwImageSizeLimit + pMemModule->pParams->dwPageSize - 1;
  // dwImageSizeLimit &= ~(pMemModule->pParams->dwPageSize - 1);

  // Reserve virtual memory
  LPVOID lpBase = pfnVirtualAlloc((LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), dwImageSizeLimit,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  // Failed to reserve space at ImageBase, then it's up to the system
  if (NULL == lpBase) {
    // Reserver memory in arbitrary address
    lpBase = pfnVirtualAlloc(NULL, dwImageSizeLimit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // Failed again, return
    if (NULL == lpBase) {
      pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
      return FALSE;
    }
  }

  // Commit memory for PE header
  LPVOID pDest = pfnVirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
  if (!pDest) {
    pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
    return FALSE;
  }

  // Copy the data of PE header to the memory allocated
  mml_memmove(pDest, lpPeModuleBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);

  // Store the base address of this module.
  pMemModule->lpBase = pDest;
  pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
  pMemModule->bLoadOk = TRUE;

  // Get the DOS header, NT header and Section header from the new PE header
  // buffer
  pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
  pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
  pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  // Map all section data into the memory
  LPVOID pSectionBase = NULL;
  LPVOID pSectionDataSource = NULL;
  for (int i = 0; i < nNumberOfSections; ++i) {
    if (0 != pImageSectionHeader[i].VirtualAddress) {
      // Get the section base
      pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

      if (0 == pImageSectionHeader[i].SizeOfRawData) {
        DWORD size = 0;
        if (pImageSectionHeader[i].Misc.VirtualSize > 0) {
          size = pImageSectionHeader[i].Misc.VirtualSize;
        } else {
          size = pImageNtHeader->OptionalHeader.SectionAlignment;
        }

        if (size > 0) {
          // If the size is zero, but the section alignment is not zero then
          // allocate memory with the alignment
          pDest = pfnVirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE);
          if (NULL == pDest) {
            pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
            return FALSE;
          }

          // Always use position from file to support alignments smaller than
          // page size.
          mml_memset(pSectionBase, 0, size);
        }
      } else {
        // Commit this section to target address
        pDest = pfnVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
        if (NULL == pDest) {
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
BOOL
RelocateModuleBase(PMEM_MODULE pMemModule) {
  // Validate the parameters
  if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

  // Get the delta of the real image base with the predefined
  LONGLONG lBaseDelta = ((PBYTE)pMemModule->iBase - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase);

  // This module has been loaded to the ImageBase, no need to do relocation
  if (0 == lBaseDelta)
    return TRUE;

  if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
      0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    return TRUE;

  PIMAGE_BASE_RELOCATION pImageBaseRelocation =
      MakePointer(PIMAGE_BASE_RELOCATION, pMemModule->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

  if (NULL == pImageBaseRelocation) {
    pMemModule->dwErrorCode = MMEC_INVALID_RELOCATION_BASE;
    return FALSE;
  }

  while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock)) {
    PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

    int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

    for (int i = 0; i < NumberOfRelocationData; i++) {
      if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) {
        PDWORD pAddress =
            (PDWORD)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
        *pAddress += (DWORD)lBaseDelta;
      }

#ifdef _WIN64
      if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) {
        PULONGLONG pAddress =
            (PULONGLONG)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
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
BOOL
ResolveImportTable(PMEM_MODULE pMemModule) {
  if (NULL == pMemModule || NULL == pMemModule->pApis || NULL == pMemModule->pImageDosHeader)
    return FALSE;

  Type_GetModuleHandleA pfnGetModuleHandleA = (Type_GetModuleHandleA)(pMemModule->pApis->pfnGetModuleHandleA);
  Type_LoadLibraryA pfnLoadLibraryA = (Type_LoadLibraryA)(pMemModule->pApis->pfnLoadLibraryA);
  Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)(pMemModule->pApis->pfnGetProcAddress);

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

  if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
      pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    return TRUE;

  PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =
      MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pMemModule->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {
    // Get the dependent module name
    PCHAR pDllName = MakePointer(PCHAR, pMemModule->lpBase, pImageImportDescriptor->Name);

    // Get the dependent module handle
    HMODULE hMod = pfnGetModuleHandleA(pDllName);

    // Load the dependent module
    if (NULL == hMod)
      hMod = pfnLoadLibraryA(pDllName);

    // Failed
    if (NULL == hMod) {
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
    PIMAGE_THUNK_DATA pIATThunk =
        MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);

    for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
      FARPROC lpFunction = NULL;
      if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
        lpFunction = pfnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
      } else {
        PIMAGE_IMPORT_BY_NAME pImageImportByName =
            MakePointer(PIMAGE_IMPORT_BY_NAME, pMemModule->lpBase, pOriginalThunk->u1.AddressOfData);

        lpFunction = pfnGetProcAddress(hMod, (LPCSTR) & (pImageImportByName->Name));
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
BOOL
SetMemProtectStatus(PMEM_MODULE pMemModule) {
  if (NULL == pMemModule || NULL == pMemModule->pApis)
    return FALSE;

  int ProtectionMatrix[2][2][2] = {
      {
          // not executable
          {PAGE_NOACCESS, PAGE_WRITECOPY},
          {PAGE_READONLY, PAGE_READWRITE},
      },
      {
          // executable
          {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
          {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
      },
  };

  Type_VirtualProtect pfnVirtualProtect = (Type_VirtualProtect)(pMemModule->pApis->pfnVirtualProtect);
  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfnVirtualFree);

  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->lpBase);

  ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
  ulBaseHigh = (pMemModule->iBase & 0xffffffff00000000);
#endif

  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

  int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
  PIMAGE_SECTION_HEADER pImageSectionHeader =
      MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) {
    DWORD protectFlag = 0;
    DWORD oldProtect = 0;
    BOOL isExecutable = FALSE;
    BOOL isReadable = FALSE;
    BOOL isWritable = FALSE;

    BOOL isNotCache = FALSE;
    ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
    DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
    if (0 == dwSecionSize)
      continue;

    // This section is in this page
    DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

    // Discardable
    if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
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
    if (isNotCache)
      protectFlag |= PAGE_NOCACHE;
    if (!pfnVirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect)) {
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
BOOL
ExecuteTLSCallback(PMEM_MODULE pMemModule) {
  if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

  IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (imageDirectoryEntryTls.VirtualAddress == 0)
    return TRUE;

  PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pMemModule->iBase + imageDirectoryEntryTls.VirtualAddress);
  PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
  if (callback) {
    while (*callback) {
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
BOOL
CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason) {
  if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

  Type_DllMain pfnModuleEntry = NULL;

  // If there is no entry point return false
  if (0 == pImageNtHeader->OptionalHeader.AddressOfEntryPoint) {
    return FALSE;
  }

  pfnModuleEntry = MakePointer(Type_DllMain, pMemModule->lpBase, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

  if (NULL == pfnModuleEntry) {
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
FARPROC
GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName) {
  if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
    return NULL;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

  PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
      MakePointer(PIMAGE_EXPORT_DIRECTORY, pMemModule->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  PDWORD pAddressOfNames = MakePointer(PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNames);

  PWORD pAddressOfNameOrdinals = MakePointer(PWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNameOrdinals);

  PDWORD pAddressOfFunctions = MakePointer(PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfFunctions);

  int nNumberOfFunctions = pImageExportDirectory->NumberOfFunctions;
  for (int i = 0; i < nNumberOfFunctions; ++i) {
    DWORD dwAddressOfName = pAddressOfNames[i];

    LPCSTR pFunctionName = MakePointer(LPCSTR, pMemModule->lpBase, dwAddressOfName);

    if (0 == mml_strcmpA(lpName, pFunctionName)) {
      WORD wOrdinal = pAddressOfNameOrdinals[i];
      DWORD dwFunctionOffset = pAddressOfFunctions[wOrdinal];
      FARPROC pfnTargetProc = MakePointer(FARPROC, pMemModule->lpBase, dwFunctionOffset);

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
VOID
UnmapMemModule(PMEM_MODULE pMemModule) {
  if (NULL == pMemModule || NULL == pMemModule->pApis || FALSE == pMemModule->bLoadOk || NULL == pMemModule->lpBase)
    return;

  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfnVirtualFree);

  pfnVirtualFree(pMemModule->lpBase, 0, MEM_RELEASE);

  pMemModule->lpBase = NULL;
  pMemModule->dwCrc = 0;
  pMemModule->dwSizeOfImage = 0;
  pMemModule->bLoadOk = FALSE;
}

/// <summary>
/// Gets the CRC32 of the data.
/// </summary>
/// <param name="uInit">Number used to initialize.</param>
/// <param name="pBuf">The Buffer.</param>
/// <param name="nBufSize">The size of the buffer.</param>
UINT32
GetCRC32(UINT32 uInit, void *pBuf, UINT32 nBufSize) {
#define CRC32_POLY 0x04C10DB7L
  UINT32 crc = 0;
  UINT32 Crc32table[256];
  for (int i = 0; i < 256; i++) {
    crc = (UINT32)(i << 24);
    for (int j = 0; j < 8; j++) {
      if (crc >> 31)
        crc = (crc << 1) ^ CRC32_POLY;
      else
        crc = crc << 1;
    }
    Crc32table[i] = crc;
  }

  crc = uInit;
  UINT32 nCount = nBufSize;
  PUCHAR p = (PUCHAR)pBuf;
  while (nCount--) {
    crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
  }

  return crc;
}

/// <summary>
/// Gets the length of the ANSI string.
/// </summary>
/// <param name="psz">The string.</param>
int
mml_strlenA(const char *psz) {
  int i = 0;
  for (; *psz; psz++, i++)
    ;
  return i;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int
mml_strcmpA(const char *psza, const char *pszb) {
  unsigned char c1 = 0;
  unsigned char c2 = 0;

  do {
    c1 = (unsigned char)*psza++;
    c2 = (unsigned char)*pszb++;
    if (c1 == 0)
      return c1 - c2;
  } while (c1 == c2);

  return c1 - c2;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int
mml_stricmpW(const wchar_t *pwsza, const wchar_t *pwszb) {
  unsigned short c1 = 0;
  unsigned short c2 = 0;

  do {
    c1 = (unsigned short)*pwsza++;
    if (c1 >= 65 && c1 <= 90) {
      c1 = c1 + 32;
    }

    c2 = (unsigned short)*pwszb++;
    if (c2 > 65 && c2 < 90) {
      c2 = c2 + 32;
    }

    if (c1 == 0)
      return c1 - c2;
  } while (c1 == c2);

  return c1 - c2;
}

/// <summary>
/// Copys the string from source to destination buffer.
/// </summary>
/// <param name="pszDest">The destination string buffer.</param>
/// <param name="pszSrc">The source string.</param>
/// <param name="nMax">Maximum count of the character to copy.</param>
wchar_t *
mml_strcpyW(wchar_t *pszDest, const wchar_t *pszSrc, unsigned int nMax) {
  while (nMax--) {
    *pszDest++ = *pszSrc++;
    if (*pszSrc == 0)
      break;
  }
  return pszDest;
}

#pragma optimize("gtpy", off)
/// <summary>
/// Sets the memory with specific value.
/// </summary>
void *
mml_memset(void *pv, int c, unsigned int cb) {
  for (unsigned int i = 0; i < cb; i++)
    ((unsigned char *)pv)[i] = (unsigned char)c;
  return pv;
}
#pragma optimize("gtpy", on)

/// <summary>
/// Moves the source memory data to the destination buffer.
/// </summary>
/// <param name="pvDest">The destination buffer.</param>
/// <param name="pvSrc">The source memory buffer.</param>
/// <param name="cb">The count of the bytes to move.</param>
void *
mml_memmove(void *pvDest, const void *pvSrc, unsigned int cb) {
  unsigned char *pb1 = 0;
  unsigned char *pb2 = 0;

  if (pvSrc < pvDest) {
    pb1 = (unsigned char *)pvDest + cb - 1;
    pb2 = (unsigned char *)pvSrc + cb - 1;
    for (; cb; cb--)
      *pb1-- = *pb2--;
  } else if (pvSrc > pvDest) {
    pb1 = (unsigned char *)pvDest;
    pb2 = (unsigned char *)pvSrc;
    for (; cb; cb--)
      *pb1++ = *pb2++;
  }
  return pvDest;
}

/// <summary>
/// Mark.
/// </summary>
void
mmLoaderCodeEnd() {
  return;
}

#pragma endregion mmLoaderImpl
