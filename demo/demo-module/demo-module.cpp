// demo-module.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "demo-module.h"

// This is an example of an exported function.
DEMOMODULE_API int demoFunction(void)
{
	return ::MessageBoxA(NULL, "This Message is displayed from memory module.", "", MB_OK);
}

