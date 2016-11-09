// demo-module.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "demo-module.h"

// This is an example of an exported function.
DEMOMODULE_API BOOL _stdcall demoFunction(unsigned char* buffer, unsigned int size)
{
	if (!buffer)
		return FALSE;

	char* p = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
	memcpy_s(buffer, size, p, strlen(p));
	return TRUE;
}