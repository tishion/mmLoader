/********************************************************************
	created:	2014/03/13
	created:	13:3:2014   14:52
	file base:	strmem
	file ext:	cxx
	author:		tishion
	
	purpose:	
*********************************************************************/
//+----------------------------------------------------------------------------
//  Function:   _tcslen
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
int Dw_strlenA(const char* psz)
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
int Dw_strcmpA(
	const char* psza,
	const char* pszb)
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
wchar_t* Dw_strcpyW(
	wchar_t* pszDest,
	const wchar_t* pszSrc,
	unsigned int nMax)
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
//  Function:   memset
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
#pragma optimize( "gtpy", off )
void* Dw_memset(
	void* pv,
	int c,
	unsigned int cb)
{
	for (unsigned int i=0; i < cb; i++)
		((unsigned char*)pv)[i] = (unsigned char)c;
	return pv;
}
#pragma optimize( "gtpy", on ) 


//+----------------------------------------------------------------------------
//  Function:   memmove
//
//  Synopsis:
//
//-----------------------------------------------------------------------------
void* Dw_memmove(
	void* pvDest,
	const void* pvSrc,
	unsigned int cb)
{
	unsigned char* pb1;
	unsigned char* pb2;

	if (pvSrc < pvDest)
	{
		pb1 = (unsigned char*)pvDest + cb - 1;
		pb2 = (unsigned char*)pvSrc  + cb - 1;
		for (; cb; cb--)
		{
			*pb1-- = *pb2--;	//windows 2k 源码怎么能这样写……
		}
	}
	else if (pvSrc > pvDest)
	{
		pb1 = (unsigned char*)pvDest;
		pb2 = (unsigned char*)pvSrc;
		for (; cb; cb--)
		{
			*pb1++ = *pb2++;
		}
	}
	return pvDest;
}
