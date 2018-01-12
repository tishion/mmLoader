#ifndef __CRC_H__
#define __CRC_H__
#pragma once

#define CRC32_POLY	0x04C10DB7L	

/// <summary>
/// Gets the CRC32 of the data.
/// </summary>
/// <param name="uInit">Number used to initialize.</param>
/// <param name="pBuf">The Buffer.</param>
/// <param name="nBufSize">The size of the buffer.</param>
unsigned int mml_getcrc32(unsigned int uInit, void* pBuf, unsigned int nBufSize)
{
    unsigned int crc = 0;
    unsigned int Crc32table[256];
    for (int i = 0; i < 256; i++)
    {
        crc = (unsigned int)(i << 24);
        for (int j = 0; j < 8; j++)
        {
            if (crc >> 31) crc = (crc << 1) ^ CRC32_POLY;
            else crc = crc << 1;
        }
        Crc32table[i] = crc;
    }

    crc = uInit;
    unsigned int nCount = nBufSize;
    unsigned char* p = (unsigned char*)pBuf;
    while (nCount--) crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];

    return crc;
}

#endif // __CRC_H__