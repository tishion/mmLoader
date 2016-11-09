// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the DEMOMODULE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// DEMOMODULE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DEMOMODULE_EXPORTS
#define DEMOMODULE_API __declspec(dllexport)
#else
#define DEMOMODULE_API __declspec(dllimport)
#endif

// This class is exported from the demo-module.dll
DEMOMODULE_API BOOL _stdcall demoFunction(unsigned char* buffer, unsigned int size);
