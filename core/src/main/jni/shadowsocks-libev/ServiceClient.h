#ifndef SAMA_SERVICE_CLIENT_H__
#define SAMA_SERVICE_CLIENT_H__
#pragma once
#include <string>
#include "common/NodeInfo.h"
#include "ServiceLocal.h"

int SetNodeInfo2(const sama::business::CNodeInfo& auditor, const sama::business::CNodeInfo& worker, bool bDirectServer, const char* pubKey, const char* s_path);
int StartTcpClient(const std::string& listenIp, const uint16_t listenPort);
void StopTcpClient();
void QuitTcpClient();

#endif