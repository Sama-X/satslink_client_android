#pragma once

#include <string>

class Encode {
public:
    static std::string HexEncode(const std::string& str);
    static std::string HexDecode(const std::string& str);
    static std::string HexSubstr(const std::string& str);
    static std::string Base64Encode(const std::string& str);
    static std::string Base64Decode(const std::string& str);
    static std::string Base64Substr(const std::string& str);
};