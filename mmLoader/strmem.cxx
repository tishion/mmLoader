/********************************************************************
	created:	2014/03/13
	created:	13:3:2014   14:52
	file base:	strmem
	file ext:	cxx
	author:		tishion
	
	purpose:	
*********************************************************************/
#include <Windows.h>

//+----------------------------------------------------------------------------
//  Function:   _tcslen
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
extern "C" size_t __cdecl
Dw_strlenA(
		  const char *   psz)
{
	int i = 0;
	for (size_t i=0; *psz; psz++, i++);
	return i;
}


//+----------------------------------------------------------------------------
//  Function:   strcmp
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
extern "C" int __cdecl
Dw_strcmpA(
		  const char *   psza,
		  const char *   pszb)
{
	unsigned char c1 = 0;
	unsigned char c2 = 0;

	do
	{
		c1 = (unsigned char) *psza++;
		c2 = (unsigned char) *pszb++;
		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}

//+----------------------------------------------------------------------------
//  Function:   memcmp
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
extern "C" wchar_t * __cdecl
Dw_strcpyW(
		  wchar_t *          pszDest,
		  const wchar_t *    pszSrc,
		  size_t          nMax)
{
	while (nMax--)
	{
		*pszDest++ = *pszSrc++;
		if (*pszSrc == 0)
			break;
	}
	return pszDest;
}

//+----------------------------------------------------------------------------
//  Function:   memcmp
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
/*
extern "C" int __cdecl
Dw_memcmp(
		  const void *    pv1,
		  const void *    pv2,
		  size_t          cb)
{
	size_t  i;
	int     d;
	for (i=0, d=0; i < cb && !d; i++)
		d = (*(const BYTE *)pv1) - (*(const BYTE *)pv2);
	return d;
}
*/

//+----------------------------------------------------------------------------
//  Function:   memcpy
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
/*
extern "C" void * __cdecl
Dw_memcpy(
		  void *          pvDest,
		  const void *    pvSrc,
		  size_t          cb)
{
	for (size_t i=0; i < cb; i++)
		((BYTE *)pvDest)[i] = ((const BYTE *)pvSrc)[i];
	return pvDest;
}
*/

//+----------------------------------------------------------------------------
//  Function:   memset
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
#pragma optimize( "gtpy", off )
extern "C" void * __cdecl
Dw_memset(
		  void *  pv,
		  int     c,
		  size_t  cb)
{
	for (size_t i=0; i < cb; i++)
		((BYTE *)pv)[i] = (BYTE)c;
	return pv;
}
#pragma optimize( "gtpy", on ) 


//+----------------------------------------------------------------------------
//  Function:   memmove
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
extern "C" void * __cdecl
Dw_memmove(
		   void *          pvDest,
		   const void *    pvSrc,
		   size_t          cb)
{
	BYTE *  pb1;
	BYTE *  pb2;

	if (pvSrc < pvDest)
	{
		pb1 = (BYTE *)pvDest + cb - 1;
		pb2 = (BYTE *)pvSrc  + cb - 1;
		for (; cb; cb--)
		{
			*pb1-- = *pb2--;	//windows 2k 源码怎么能这样写……
		}
	}
	else if (pvSrc > pvDest)
	{
		pb1 = (BYTE *)pvDest;
		pb2 = (BYTE *)pvSrc;
		for (; cb; cb--)
		{
			*pb1++ = *pb2++;
		}
	}
	return pvDest;
}
