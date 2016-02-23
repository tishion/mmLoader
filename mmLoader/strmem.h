
#ifndef STRMEM_H
#define STRMEM_H
int Dw_strlenA(const char* psz);

int Dw_strcmpA(
	const char* psza,
	const char* pszb);

wchar_t* Dw_strcpyW(
	wchar_t* pszDest,
	const wchar_t* pszSrc,
	unsigned int nMax);

void* Dw_memset(
	void* pv,
	int c,
	unsigned int cb);

void* Dw_memmove(
	void* pvDest,
	const void* pvSrc,
	unsigned int cb);

#endif
