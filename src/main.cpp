#include <string>
#include <iostream>

#include <phpcpp.h>

#include "crypt.h"

crypt_t crypt;

Php::Value mu_decoder_init(Php::Parameters &params)
{
    if (params.size() < 2) {
        return false;
    }

    try {
        //loading keys
        crypt.startup(params[0].stringValue(), params[1].stringValue());
    } catch(std::exception &e) {
        std::cout << "Unable to load files: " << e.what() << std::endl;
        return false;
    }

    return true;
}

Php::Value mu_decode_c3(Php::Parameters &params)
{
    if (params.size() < 1 || !crypt.isLoaded()) {
        return false;
    }

    //converting string to char array
    const unsigned char* src = reinterpret_cast<const unsigned char*>(params[0].stringValue().c_str());

    //decrypting
    unsigned char dst[512] = {0};
    int decLength = crypt.decrypt(dst + 1, src + 2, (size_t) src[1] - 2);
    decLength += 1;

    //setting packet class
    dst[0] = static_cast<unsigned char>(src[0] - 2);
    //setting packet length
    dst[1] = static_cast<unsigned char>(decLength);

    //extracting data
    crypt.extract(dst, (size_t) decLength);

    //decrypting login and password for specific packet
    if (dst[2] == 0xF1 && dst[3] == 0x01) {
        crypt.cryptLogin(&dst[4], 10);
        crypt.cryptLogin(&dst[14], 10);
    }

    if (params.size() == 4) {
        //class
        params[1] = (uint8_t) dst[0];
        //head code
        params[2] = (uint8_t) dst[2];
        //sub code
        params[3] = (uint8_t) dst[3];
    }

    return std::string((const char*)dst, dst[1]);
}

extern "C"
{
PHPCPP_EXPORT void *get_module()
{
    static Php::Extension extension("muext","0.1");

    extension.add("mu_decode_c3", mu_decode_c3, {
            Php::ByVal("data", Php::Type::String),
            Php::ByRef("class", Php::Type::Numeric),
            Php::ByRef("head", Php::Type::Numeric),
            Php::ByRef("sub", Php::Type::Numeric)
    });

    extension.add("mu_decoder_init", mu_decoder_init, {
            Php::ByVal("encodeFileName", Php::Type::String),
            Php::ByVal("decodeFileName", Php::Type::String)
    });

//    extension.add("mu_encode_c3", mu_encode_c3, {
//            Php::ByVal("data", Php::Type::String),
//            Php::ByVal("head", Php::Type::Numeric),
//            Php::ByVal("sub", Php::Type::Numeric)
//    });

    return extension.module();
}
}