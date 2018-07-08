#ifndef __MMLOADER_H_INCLUDED_
#define __MMLOADER_H_INCLUDED_
#pragma once
#include <windows.h>

/// <summary>
/// Error codes.
/// </summary>
#define MMEC_OK                         0
#define MMEC_BAD_PE_FORMAT              1
#define MMEC_ALLOCATED_MEMORY_FAILED    2
#define MMEC_INVALID_RELOCATION_BASE    3
#define MMEC_IMPORT_MODULE_FAILED       4
#define MMEC_PROTECT_SECTION_FAILED     5
#define MMEC_INVALID_ENTRY_POINT        6

/// <summary>
/// Function table. These function will be used in the mmLoader.
/// </summary>
typedef struct __NTFUNCPTRS
{
    LPVOID pfnGetModuleHandleA;         // GetModuleHandleA
    LPVOID pfnLoadLibraryA;             // LoadLibraryA
    LPVOID pfnGetProcAddress;           // GetProcAddress
    LPVOID pfnVirtualAlloc;             // VirtualAlloc
    LPVOID pfnVirtualFree;              // VirtualFree
    LPVOID pfnVirtualProtect;           // VirtualProtect
    LPVOID pfnReversed_0;
    LPVOID pfnReversed_1;
    LPVOID pfnReversed_2;
    LPVOID pfnReversed_3;
    LPVOID pfnReversed_4;
} NTFUNCPTRSTABLE, *PNTFUNCPTRSTABLE;

/// <summary>
/// Represents the memory module instance.
/// </summary>
typedef struct __MEMMODULE
{
    union                                // MemModule base
    {
#if _WIN64
        ULONGLONG    iBase;
#else
        DWORD        iBase;
#endif
        HMODULE        hModule;
        LPVOID        lpBase;
        PIMAGE_DOS_HEADER pImageDosHeader;
    };

    DWORD dwSizeOfImage;                // MemModule size
    DWORD dwCrc;                        // MemModule crc32
    DWORD dwPageSize;                   // SystemPageSize
    BOOL  bLoadOk;                      // MemModule is loaded ok?

    PNTFUNCPTRSTABLE pNtFuncptrsTable;  // Pointer to NT function pointers table 

    DWORD  dwErrorCode;                 // Last error code

    __MEMMODULE()
    {
        iBase = 0;
        dwSizeOfImage = 0;
        dwCrc = 0;
        bLoadOk = 0;
        pNtFuncptrsTable = 0;
        dwErrorCode = 0;
        
        SYSTEM_INFO sysInfo;
        ::GetNativeSystemInfo(&sysInfo);
        dwPageSize = sysInfo.dwPageSize;
    }
} MEM_MODULE, *PMEM_MODULE;

/// <summary>
/// Enums for MemModuleHelper.
/// </summary>
typedef enum _MMHELPER_METHOD
{
    MHM_BOOL_LOAD,                      // Call LoadMemModule
    MHM_VOID_FREE,                      // Call FreeMemModule
    MHM_FARPROC_GETPROC,                // Call GetMemModuleProc
} MMHELPER_METHOD;

/// <summary>
/// Helper function for using shell code.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="method">The <see cref="MMHELPER_METHOD"> to call.</param>
/// <param name="lpPeModuleBuffer">The buffer containing the raw data of the module.</param>
/// <param name="lpName">The function name.</param>
/// <returns>True if the module is loaded successfully.</returns>
/// <returns>
/// If method is MHM_BOOL_LOAD:
///     The return value type is BOOL.
///
/// If method is MHM_FARPROC_GETPROC
///     The return value type if FARPROC.
///
/// If method is MHM_VOID_FREE
///        There is no return value.
/// </returns>
typedef LPVOID(__stdcall * Type_MemModuleHelper)(PMEM_MODULE, MMHELPER_METHOD, LPVOID, LPCSTR, BOOL);

/// <summary>
/// Helper function for using shell code.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="method">The <see cref="MMHELPER_METHOD"> to call.</param>
/// <param name="lpPeModuleBuffer">The buffer containing the raw data of the module.</param>
/// <param name="lpName">The function name.</param>
/// <returns>True if the module is loaded successfully.</returns>
/// <returns>
/// If method is MHM_BOOL_LOAD:
///     The return value type is BOOL.
///
/// If method is MHM_FARPROC_GETPROC
///     The return value type if FARPROC.
///
/// If method is MHM_VOID_FREE
///     There is no return value.
/// </returns>
LPVOID __stdcall
MemModuleHelper(
    _Inout_ PMEM_MODULE pMmeModule, 
    _In_ MMHELPER_METHOD method, 
    _In_ LPVOID lpPeModuleBuffer,
    _In_ LPCSTR lpProcName,
    _In_ BOOL bCallEntry);

/// <summary>
/// Loads the memory module.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="lpPeModuleBuffer">The buffer containing the raw data of the module.</param>
/// <param name="bCallEntry">Call the module entry if true.</param>
/// <returns>True if the module is loaded successfully.</returns>
BOOL __stdcall
LoadMemModule(
    _Out_ PMEM_MODULE pMemModule,
    _In_ LPVOID lpPeModuleBuffer, 
    _In_ BOOL bCallEntry);

/// <summary>
/// Gets the process address of the specific function in the memory module.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="lpName">The function name.</param>
/// <returns>The address of the function or null.</returns>
FARPROC __stdcall
GetMemModuleProc(
    _In_ PMEM_MODULE pMemModule,
    _In_ LPCSTR lpName);

/// <summary>
/// Frees the memory module.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
VOID __stdcall
FreeMemModule(_In_ PMEM_MODULE pMemModule);

#endif // __MMLOADER_H_INCLUDED_