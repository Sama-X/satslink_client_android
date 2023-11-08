#include "samapacket.h"
#include <string.h>

void SAMA_Packet_Auditor(unsigned short version, const char* pubKey, const char* auditorData, const int len, char* sendData, int* sendLen)
{
    int offset = 2 + 33 + 4 + len;
    memmove(sendData + offset, sendData, *sendLen);
    *sendLen += offset;
    offset = 0;
    memcpy(sendData + offset, &version, 2); offset += 2;
    memcpy(sendData + offset, pubKey, 33); offset += 33;
    memcpy(sendData + offset, &len, 4); offset += 4;
    memcpy(sendData + offset, auditorData, len); offset += len;
}

void SAMA_Packet_Worker(unsigned short version, const char* pubKey, char* sendData, int* sendLen)
{
    int offset = 2 + 33;
    memmove(sendData + offset, sendData, *sendLen);
    *sendLen += offset;
    offset = 0;
    memcpy(sendData + offset, &version, 2); offset += 2;
    memcpy(sendData + offset, pubKey, 33); offset += 33;
}