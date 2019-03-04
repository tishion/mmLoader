#ifndef __MMLOADER_H_INCLUDED_
#define __MMLOADER_H_INCLUDED_
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Error codes.
/// </summary>
#define MMEC_OK 0
#define MMEC_BAD_PE_FORMAT 1
#define MMEC_ALLOCATED_MEMORY_FAILED 2
#define MMEC_INVALID_RELOCATION_BASE 3
#define MMEC_IMPORT_MODULE_FAILED 4
#define MMEC_PROTECT_SECTION_FAILED 5
#define MMEC_INVALID_ENTRY_POINT 6
#define MMEC_INVALID_WIN32_ENV 0xff

/// <summary>
/// Enums for MemModuleHelper.
/// </summary>
typedef enum _MMHELPER_METHOD {
  MHM_BOOL_LOAD,       // Call LoadMemModule
  MHM_VOID_FREE,       // Call FreeMemModule
  MHM_FARPROC_GETPROC, // Call GetMemModuleProc
} MMHELPER_METHOD;

typedef void **HMEMMODULE;

/// <summary>
/// Helper function for using shell code.
/// </summary>
typedef LPVOID(__stdcall *Type_MemModuleHelper)(MMHELPER_METHOD, LPVOID, LPVOID, LPVOID);

/// <summary>
/// Helper function for using shell code.
/// </summary>
/// <remarks>
/// If the method == MHM_BOOL_LOAD, then the function performs the LoadMemModule function.
/// If the method == MHM_VOID_FREE, then the function performs the FreeMemModule function.
/// If the method == MHM_FARPROC_GETPROC, then the function performs the GetMemModuleProc function.
/// </remarks>
LPVOID
MemModuleHelper(_In_ MMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3);

/// <summary>
/// Loads the memory module.
/// </summary>
/// <param name="lpPeModuleBuffer">The buffer containing the raw data of the module.</param>
/// <param name="bCallEntry">Call the module entry if true.</param>
/// <param name="pdwError">The error code.</param>
/// <returns>The handle to the memory module instance or NULL.</returns>
HMEMMODULE
LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD *pdwError);

/// <summary>
/// Gets the process address of the specific function in the memory module.
/// </summary>
/// <param name="MemModuleHandle">The handle to the memory module instance.</param>
/// <param name="lpName">The function name.</param>
/// <returns>The address of the function or null.</returns>
FARPROC
GetMemModuleProc(_In_ HMEMMODULE MemModuleHandle, _In_ LPCSTR lpName);

/// <summary>
/// Frees the memory module.HMEMMODULE
/// </summary>
/// <param name="MemModuleHandle">The handle to the memory module instance.</param>
VOID
FreeMemModule(_In_ HMEMMODULE MemModuleHandle);

#ifdef __cplusplus
}
#endif

#endif // __MMLOADER_H_INCLUDED_
