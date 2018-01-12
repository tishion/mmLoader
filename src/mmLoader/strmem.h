#ifndef __STRMEM_H__
#define __STRMEM_H__
#pragma once

/// <summary>
/// Gets the length of the ANSI string.
/// </summary>
/// <param name="psz">The string.</param>
int mml_strlenA(const char* psz)
{
    int i = 0;
    for (; *psz; psz++, i++);
    return i;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int mml_strcmpA(const char* psza, const char* pszb)
{
    unsigned char c1 = 0;
    unsigned char c2 = 0;

    do
    {
        c1 = (unsigned char)*psza++;
        c2 = (unsigned char)*pszb++;
        if (c1 == 0) return c1 - c2;
    } while (c1 == c2);

    return c1 - c2;
}

/// <summary>
/// Copys the string from source to destination buffer.
/// </summary>
/// <param name="pszDest">The destination string buffer.</param>
/// <param name="pszSrc">The source string.</param>
/// <param name="nMax">Maximum count of the character to copy.</param>
wchar_t* mml_strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax)
{
    while (nMax--)
    {
        *pszDest++ = *pszSrc++;
        if (*pszSrc == 0) break;
    }
    return pszDest;
}

#pragma optimize( "gtpy", off )
/// <summary>
/// Sets the memory with specific value.
/// </summary>
void* mml_memset(void* pv, int c, unsigned int cb)
{
    for (unsigned int i = 0; i < cb; i++) ((unsigned char*)pv)[i] = (unsigned char)c;
    return pv;
}
#pragma optimize( "gtpy", on ) 

/// <summary>
/// Moves the source memory data to the destination buffer.
/// </summary>
/// <param name="pvDest">The destination buffer.</param>
/// <param name="pvSrc">The source memory buffer.</param>
/// <param name="cb">The count of the bytes to move.</param>
void* mml_memmove(void* pvDest, const void* pvSrc, unsigned int cb)
{
    unsigned char* pb1 = 0;
    unsigned char* pb2 = 0;

    if (pvSrc < pvDest)
    {
        pb1 = (unsigned char*)pvDest + cb - 1;
        pb2 = (unsigned char*)pvSrc + cb - 1;
        for (; cb; cb--) *pb1-- = *pb2--;
    }
    else if (pvSrc > pvDest)
    {
        pb1 = (unsigned char*)pvDest;
        pb2 = (unsigned char*)pvSrc;
        for (; cb; cb--) *pb1++ = *pb2++;
    }
    return pvDest;
}

#endif // __STRMEM_H__