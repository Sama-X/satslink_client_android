#include "GlobalOperate.h"
#include "json/json.h"
#include "encode.h"
#include "yrc4.h"
#include <iostream>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace sama{
namespace business{


bool IpChange(const std::string& ip, bool& isIpv4, uint32_t& ipV4, char* ipV6)
{
    std::cout << "IpChange::" << ip << std::endl;
    bool bRet = false;
    int a;
    bRet = ::inet_pton(AF_INET, ip.c_str(), &a) == 1;
    if(bRet)
    {
        isIpv4 = true;
        ipV4 = (uint32_t)a;
        return true;
    }
    char c[16];
    bRet = ::inet_pton(AF_INET6, ip.c_str(), c) == 1;
    if(bRet)
    {
        isIpv4 = false;
        memcpy(ipV6, c, 16);
        return true;
    }
    return false;
}

static std::string g_yrc4PassWord = "sama_h_l_!@#dbzx!!*&";

bool GlobalOperate::DeralizeSSInfo2(const std::string& base64, CNodeInfo& auditor, CNodeInfo& worker, bool& bDirectServer, std::string& publicKey, int& port)
{
    std::cout << "start DeralizeSSInfo2\n";
    bool bRet = false;
    do
    {
        std::string yrc4Str = Encode::Base64Decode(base64);
        unsigned char* res2 = new unsigned char[yrc4Str.size()];
        yrc4((unsigned char*)g_yrc4PassWord.c_str(), g_yrc4PassWord.length(), (unsigned char*)yrc4Str.c_str(), yrc4Str.length(), res2);
        Json::Reader reader;
        Json::Value Jroot;
        std::string jsonContent = std::string((char*)res2, yrc4Str.size());
        std::cout << jsonContent << std::endl;
        delete[] res2;
        if (!reader.parse(jsonContent, Jroot))
        {
            std::cout << "json parse error\n";
            return false;
        }
        uint64_t nStartTime = Jroot["time"].asUInt64();
        if (abs(int(nStartTime - time(0))) >= 5)
        {
            std::cout << "Token expires and becomes invalid\n";
            return false;
        }
        port = Jroot["port"].asInt();
        bDirectServer = Jroot["directServer"].asBool();
        publicKey = Jroot["publicKey"].asString();
        {
            auditor.m_nIdentity = Jroot["auditor"]["stakerType"].asInt();
            auditor.strEcdh = Jroot["auditor"]["ecdh"].asString();
            auditor.m_strNetIP = Jroot["auditor"]["netip"].asString();
            memcpy(auditor.strPubKeySha256, Encode::HexDecode(Jroot["auditor"]["publicKeyHash"].asString()).c_str(), 32);
            for(int i = 0; i < 3; i++)
            {
                auditor.workPort[i] = Jroot["auditor"]["workPort"][i].asInt();
                auditor.workPort2[i] = Jroot["auditor"]["workPort2"][i].asInt();
            }
            bRet = IpChange(auditor.m_strNetIP, auditor.bIpV4, auditor.nIpv4, auditor.chIpv6);
        }
        {
            worker.m_nIdentity = Jroot["worker"]["stakerType"].asInt();
            worker.strEcdh = Jroot["worker"]["ecdh"].asString();
            worker.m_strNetIP = Jroot["worker"]["netip"].asString();
            memcpy(worker.strPubKeySha256, Encode::HexDecode(Jroot["worker"]["publicKeyHash"].asString()).c_str(), 32);
            for(int i = 0; i < 3; i++)
            {
                worker.workPort[i] = Jroot["worker"]["workPort"][i].asInt();
                worker.workPort2[i] = Jroot["worker"]["workPort2"][i].asInt();
            }
            bRet = IpChange(worker.m_strNetIP, worker.bIpV4, worker.nIpv4, worker.chIpv6);
        }
    } while (0);
    return bRet;
}

}
}