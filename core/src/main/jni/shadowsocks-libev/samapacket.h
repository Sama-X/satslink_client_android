#ifndef SAMA_SERVICE_SAMAPACKET_H__
#define SAMA_SERVICE_SAMAPACKET_H__

/*
1. version = 1
2. pubKey len is 33
3. sendData capacity must >= (2 + 33 + 4 + len + sendLen)
*/
void SAMA_Packet_Auditor(unsigned short version, const char* pubKey, const char* auditorData, const int len, char* sendData, int* sendLen);

/*
1. version = 1
2. pubKey len is 33
3. sendData capacity must >= (2 + 33 + sendLen)
*/
void SAMA_Packet_Worker(unsigned short version, const char* pubKey, char* sendData, int* sendLen);

#endif