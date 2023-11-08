#include <algorithm>
#include "NodeInfo.h"

namespace sama{
namespace business{

CNodeInfo::CNodeInfo()
{
    m_nCheckPort = 0;
    m_nMinPort = 0;
    m_nMaxPort = 0;
    m_nIdentity = 0;

    bCanConnect = false;
    bIsTestConnect = false;
}

CNodeInfo::~CNodeInfo(){}

void CNodeInfo::assign(const CNodeInfo& info)
{
    this->m_strNetIP = info.m_strNetIP;
    this->m_strCountry = info.m_strCountry;
    this->m_strPublicKey = info.m_strPublicKey;
    this->m_nCheckPort = info.m_nCheckPort;
    this->m_nMinPort = info.m_nMinPort;
    this->m_nMaxPort = info.m_nMaxPort;
    this->m_nIdentity = info.m_nIdentity;
    memcpy(strPubKeySha256, info.strPubKeySha256, 32);
    this->strEcdh = info.strEcdh;
    this->bIpV4 = info.bIpV4;
    this->nIpv4 = info.nIpv4;
    memcpy(this->chIpv6, info.chIpv6, 16);
    for(int i = 0; i < 3; ++i)
    {
        this->workPort[i] = info.workPort[i];
        this->workPort2[i] = info.workPort2[i];
    }
    this->bCanConnect = info.bCanConnect;
    this->bIsTestConnect = info.bIsTestConnect;
}

uint16_t CNodeInfo::getRandomWorkPort2()
{
    int nIndex = rand() % 3; 
    return workPort2[nIndex];
}

}
}