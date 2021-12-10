// demo-module.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#include <string>

#include "demo-module.h"

static std::string msg = "Hello World";

std::string
get_str() {
  return "hello string";
}

// This is an example of an exported function.
DEMOMODULE_API BOOL
demoFunction(unsigned char *buffer, unsigned int size) {
  if (!buffer)
    return FALSE;

  OutputDebugStringA("global static string:");
  printf("global static string:");

  OutputDebugStringA(msg.c_str());
  printf(msg.c_str());

  OutputDebugStringA("\n");
  printf("\n");

  OutputDebugStringA("local static the_string:");
  printf("local static the_string:");

  static std::string the_string = get_str(); // crash on windows xp
  if (!the_string.empty()) {
    printf(the_string.c_str());
    OutputDebugStringA(the_string.c_str());
  } else {
    // bad behavior on windows 7 and later.  string is always  emtpy
    OutputDebugStringA("empty");
    printf("empty");
  }
  OutputDebugStringA("\n");
  printf("\n");

  if (!buffer)
    return FALSE;

  std::string s = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
  memcpy_s(buffer, size, s.data(), s.length());
  return TRUE;
}