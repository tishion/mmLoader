/********************************************************************
	created:	2014/03/11
	created:	11:3:2014   14:34
	file base:	crc
	file ext:	cpp
	author:		tishion
	
	purpose:	
*********************************************************************/
#define CRC32_POLY	0x04C10DB7L	
//#define CRC32_POLY	0x04C11DB7L	

VOID InitCrc32Table(PUINT32 pCrc32Table) 
{
	UINT32 crc = 0;

	for (int i=0; i<256; i++)
	{
		crc = (UINT32)(i << 24);
		for (int j=0; j<8; j++)
		{
			if (crc >> 31)
			{
				crc  = (crc << 1) ^ CRC32_POLY;
			}
			else
			{
				crc  = crc << 1;
			}
		}
		pCrc32Table[i] = crc ;
	}

	return ;
}

UINT32 GetCrc32(UINT32 uInit, LPVOID pBuf, SIZE_T nBufSize)
{
	UINT32 crc = uInit;
	UINT32 Crc32table[256];

	InitCrc32Table(Crc32table);

	SIZE_T nCount = nBufSize;
	PBYTE p = (PBYTE)pBuf;
	while (nCount--)
	{
		crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
	}

	return crc;
}

/*
#define CRC32_POLY	0xEDB88320L	
VOID InitCrc32Table(PUINT32 pCrc32Table) 
{
	UINT32 crc = 0;

	for (int i=0; i<256; i++)
	{
		crc = (ULONG)i;
		for (int j=0; j<8; j++) 
		{
			if (crc << 31)
			{
				crc = (crc >> 1) ^ CRC32_POLY;
			}
			else      
			{
				crc = crc >> 1;
			}
		}
		pCrc32Table[i] = crc;
	}
}

UINT32 GetCrc32(UINT32 uInit, LPVOID pBuf, SIZE_T nBufSize)
{
	UINT32 crc = uInit ^ 0xFFFFFFFF;
	UINT32 Crc32table[256];

	InitCrc32Table(Crc32table);

	SIZE_T nCount = nBufSize;
	PBYTE p = (PBYTE)pBuf;
	while (nCount--)
	{
		crc = (crc >> 8) ^ Crc32table[(crc & 0xff) ^ *p++];
	}

	return crc ^ 0xFFFFFFFF;
}
*/