/********************************************************************
	created:	2014/03/11
	created:	11:3:2014   14:34
	file base:	crc
	file ext:	cpp
	author:		tishion
	
	purpose:	
*********************************************************************/
#define CRC32_POLY	0x04C10DB7L	

void InitCrc32Table(unsigned int* pCrc32Table) 
{
	unsigned int crc = 0;

	for (int i=0; i<256; i++)
	{
		crc = (unsigned int)(i << 24);
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

unsigned int GetCrc32(unsigned int uInit, void* pBuf, unsigned int nBufSize)
{
	unsigned int crc = uInit;
	unsigned int Crc32table[256];

	InitCrc32Table(Crc32table);

	unsigned int nCount = nBufSize;
	unsigned char* p = (unsigned char*)pBuf;
	while (nCount--)
	{
		crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
	}

	return crc;
}