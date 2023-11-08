#ifndef SAMA_BUSINESS_NODEINFO_H__
#define SAMA_BUSINESS_NODEINFO_H__
#pragma once
#include <string>

namespace Json{
class Value;
}

namespace sama{
namespace business{
class CNodeInfo
{
public:
    CNodeInfo();
    virtual ~CNodeInfo();
    void assign(const CNodeInfo& info);
    uint16_t getRandomWorkPort2();
public:
    std::string m_strNetIP;
    std::string m_strCountry;
    std::string m_strPublicKey;
    uint16_t m_nCheckPort;
    uint16_t m_nMinPort;
    uint16_t m_nMaxPort;
    uint16_t m_nIdentity;
public:
    char strPubKeySha256[32];
    std::string strEcdh;
    bool bIpV4;
    uint32_t nIpv4;
    char chIpv6[16];
    uint16_t workPort[3];
    uint16_t workPort2[3];
    bool bCanConnect;
    bool bIsTestConnect;
};

}
}

#endif