/********************************************************************
	created:	2014/03/13
	created:	13:3:2014   14:53
	file base:	strmem
	file ext:	h
	author:		tishion
	
	purpose:	
*********************************************************************/
#ifndef __STRMEM_H__
#define __STRMEM_H__

extern "C" size_t __cdecl
Dw_strlenA(
		  const char *   psz);

extern "C" int __cdecl
Dw_strcmpA(
		  const char *   psza,
		  const char *   pszb);

extern "C" wchar_t * __cdecl
Dw_strcpyW(
		   wchar_t *          pszDest,
		   const wchar_t *    pszSrc,
		   size_t          nMax);

//extern "C" int __cdecl
//Dw_memcmp(
//		  const void *    pv1,
//		  const void *    pv2,
//		  size_t          cb);
//
//extern "C" void * __cdecl
//Dw_memcpy(
//		  void *          pvDest,
//		  const void *    pvSrc,
//		  size_t          cb);

extern "C" void * __cdecl
Dw_memset(
		  void *  pv,
		  int     c,
		  size_t  cb);

extern "C" void * __cdecl
Dw_memmove(
		   void *          pvDest,
		   const void *    pvSrc,
		   size_t          cb);

#endif
