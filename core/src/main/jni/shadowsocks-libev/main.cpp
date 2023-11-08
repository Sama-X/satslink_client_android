#include <iostream>
#include <string>
#include "common/GlobalOperate.h"
#include "common/encode.h"
#include "ServiceClient.h"

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        std::cout << "param num error:" << argc << std::endl;
        return 0;
    }
    std::cout << argv[0] << std::endl;
    std::cout << argv[1] << std::endl;
    std::cout << argv[2] << std::endl;
    bool bDirectServer = true;
    std::string publicKey;
    int port;
    sama::business::CNodeInfo auditor, worker;
    sama::business::GlobalOperate go;
    if(!go.DeralizeSSInfo2(argv[1], auditor, worker, bDirectServer, publicKey, port))
    {
        std::cout << "DeralizeSSInfo error\n";
        return 0;
    }
    std::string publicKey2 = Encode::HexDecode(publicKey);
    SetNodeInfo2(auditor, worker, bDirectServer, publicKey2.c_str(), argv[2]);
    std::cout << "start tcp client port:" << port << std::endl;
    StartTcpClient("127.0.0.1", (uint16_t)port);
    std::cout << "end tcp client port:" << port << std::endl;
    return 0;
}
