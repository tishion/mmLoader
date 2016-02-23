#ifndef CRC_H
#define CRC_H
void InitCrc32Table(unsigned int* pCrc32Table);
unsigned int GetCrc32(unsigned int uInit, void* pBuf, unsigned int nBufSize);
#endif // !CRC_H
