#ifndef SAMA_BUSINESS_GLOBALOPERATE_H__
#define SAMA_BUSINESS_GLOBALOPERATE_H__
#pragma once

#include <string>
#include "NodeInfo.h"

namespace sama{
namespace business{

class GlobalOperate
{
public:
    GlobalOperate(){};
    ~GlobalOperate(){};
    bool DeralizeSSInfo2(const std::string& base64, CNodeInfo& auditor, CNodeInfo& worker, bool& bDirectServer, std::string& publicKey, int& port);
};

}
}


#endif