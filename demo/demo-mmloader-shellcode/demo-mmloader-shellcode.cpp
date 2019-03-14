// demo-mmloader-shellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <tchar.h>
#include <windows.h>

#include <strsafe.h>

#ifdef _WIN64
#ifdef _DEBUG
#include <mmLoaderShellCode-x64-Debug.h>
#else
#include <mmLoaderShellCode-x64-Release.h>
#endif
#else
#ifdef _DEBUG
#include <mmLoaderShellCode-x86-Debug.h>
#else
#include <mmLoaderShellCode-x86-Release.h>
#endif
#endif

class AutoReleaseModuleBuffer {
public:
  AutoReleaseModuleBuffer(LPCTSTR szDllPath) : m_pBuffer(NULL), m_hFileMapping(NULL), m_hFile(NULL) {
    // Open the module and read it into memory buffer
    m_hFile = ::CreateFile(szDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (INVALID_HANDLE_VALUE == m_hFile || NULL == m_hFile) {
      _tprintf(_T("Failed to open the file: %s\r\n"), szDllPath);
      return;
    }

    // Check file size
    DWORD dwFileSize = ::GetFileSize(m_hFile, NULL);
    if (INVALID_FILE_SIZE == dwFileSize || dwFileSize < sizeof(IMAGE_DOS_HEADER)) {
      ::CloseHandle(m_hFile);
      m_hFile = NULL;
      _tprintf(_T("Invalid file size: %d\r\n"), dwFileSize);
      return;
    }

    m_hFileMapping = ::CreateFileMappingW(m_hFile, 0, PAGE_READONLY, 0, 0, NULL);
    if (NULL == m_hFileMapping) {
      ::CloseHandle(m_hFile);
      m_hFile = NULL;
      _tprintf(_T("Failed to create file mapping.\r\n"));
      return;
    }

    m_pBuffer = ::MapViewOfFile(m_hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == m_pBuffer) {
      ::CloseHandle(m_hFileMapping);
      ::CloseHandle(m_hFile);
      m_hFileMapping = NULL;
      m_hFile = NULL;
      _tprintf(_T("Failed to map view of the file.\r\n"));
    }
  }

  ~AutoReleaseModuleBuffer() { Release(); }

  void
  Release() {
    if (m_pBuffer) {
      ::UnmapViewOfFile(m_pBuffer);
      m_pBuffer = NULL;
    }

    if (m_hFileMapping) {
      ::CloseHandle(m_hFileMapping);
      m_hFileMapping = NULL;
    }

    if (m_hFile) {
      ::CloseHandle(m_hFile);
      m_hFile = NULL;
    }
  }

  operator LPVOID() { return m_pBuffer; }

private:
  LPVOID m_pBuffer;
  HANDLE m_hFile;
  HANDLE m_hFileMapping;
};

int
main() {
  int iRet = -1;

  // Memory module
  HMEMMODULE hMemModule = NULL;
  DWORD dwErrorCode = 0;

  // Allocate memory buffer for shell code with EXECUTE privilege
  LPVOID lpShellCodeBase =
      ::VirtualAlloc(NULL, sizeof(mmLoaderShellCode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  if (NULL == lpShellCodeBase) {
    ::_tprintf(_T("Failed to allocate space for ShellCode!"));
    return iRet;
  }

  // Copy shell code to the executable memory buffer
  ::RtlCopyMemory(lpShellCodeBase, mmLoaderShellCode, sizeof(mmLoaderShellCode));

  // Get the helper function
  Type_MemModuleHelper pfnMemModuleHelper = (Type_MemModuleHelper)lpShellCodeBase;

  // Here we just read the module data from disk file
  // In your real project you can download the module data from remote without witting it to disk file
#ifdef _DEBUG
  TCHAR szDllPath[] = _T("demo-moduled.dll");
#else
  TCHAR szDllPath[] = _T("demo-module.dll");
#endif
  AutoReleaseModuleBuffer moduleBuffer(szDllPath);

  // Load the module from the buffer
  hMemModule = (HMEMMODULE)pfnMemModuleHelper(MHM_BOOL_LOAD, moduleBuffer, (LPVOID)TRUE, &dwErrorCode);

  // After the module was loaded we can release the original buffer
  moduleBuffer.Release();

  if (hMemModule) {
    _tprintf(_T("Module was load successfully. Module Base: 0x%p!\r\n"), (LPVOID)hMemModule);

    // Get address of function demoFunction
    LPVOID lpAddr = (LPVOID)pfnMemModuleHelper(MHM_FARPROC_GETPROC, hMemModule, "demoFunction", 0);
    if (lpAddr) {
      _tprintf(_T("Get address of demoFunction successfully. Address: 0x%p!\r\n"), lpAddr);

      // Function pointer type of demoFunction
      typedef BOOL(__stdcall * Type_TargetFunction)(unsigned char *, unsigned int);

      // Call the demoFunction
      Type_TargetFunction pfnFunction = (Type_TargetFunction)lpAddr;

      unsigned char buf[MAX_PATH] = {0};
      if (pfnFunction(buf, MAX_PATH)) {
        char *p = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
        iRet = ::memcmp(buf, p, strlen(p));
        if (0 == iRet)
          _tprintf(_T("Called target function demoFunction successfully with correct return value!\r\n"));
        else
          _tprintf(_T("Called target function demoFunction successfully, but returned unexpected value!\r\n"));
      }
    } else
      _tprintf(_T("Failed to get address of MessageBoxA from memory module."));

    // Free the module
    pfnMemModuleHelper(MHM_VOID_FREE, hMemModule, 0, 0);
  } else
    _tprintf(_T("Failed to load the module.!\r\n"));

  // Free the memory buffer of the shell code
  ::VirtualFree(lpShellCodeBase, 0, MEM_RELEASE);

  return iRet;
}
