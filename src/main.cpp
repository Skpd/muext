#include <string>
#include <iostream>

#include <phpcpp.h>

#include "crypt.h"

crypt_t crypt;

static unsigned char s_uSerial = 0;

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
    size_t length, decLength;
    bool isDouble = src[0] == 0xC2 || src[0] == 0xC4;

    if (isDouble) {
        length = src[1] << 8 | src[2];
    } else {
        length = src[1];
    }

    if (isDouble) {
        decLength = (size_t) crypt.decrypt(dst + 2, src + 3, length - 3) + 2;
    } else {
        decLength = (size_t) crypt.decrypt(dst + 1, src + 2, length - 2) + 1;
    }

    //setting packet class
    dst[0] = static_cast<unsigned char>(src[0] - 2);
    //setting packet length
    if (isDouble) {
        dst[1] = static_cast<unsigned char>(decLength >> 8 & 0xFF);
        dst[2] = static_cast<unsigned char>(decLength & 0xFF);
    } else {
        dst[1] = static_cast<unsigned char>(decLength);
    }

    //decrypting login and password for specific packet
    if (dst[2] == 0xF1 && dst[3] == 0x79) {
        crypt.extract(dst, decLength);

        crypt.decryptLogin(&dst[4], 10);
        crypt.decryptLogin(&dst[14], 10);
    }

    if (params.size() == 4) {
        //class
        params[1] = (uint8_t) dst[0];
        //head code
        params[2] = (uint8_t) dst[isDouble ? 3 : 2];
        //sub code
        params[3] = (uint8_t) dst[isDouble ? 4 : 3];
    }

    return std::string((const char*)dst, decLength);
}

Php::Value mu_encode_c3(Php::Parameters &params)
{
    if (params.size() < 1 || !crypt.isLoaded()) {
        return false;
    }

    //encrypting
    unsigned char dst[512] = {0};

    //converting string to char array
    unsigned char* src =(unsigned char*)(params[0].stringValue().c_str());

    unsigned char code = src[0];
    size_t length = src[1];

    //encrypting login and password for specific packet
    if ((src[2] == 0xFA && src[3] == 0x01) || (src[2] == 0xF1 && src[3] == 0x00)) {
        crypt.cryptLogin(&src[4], 10);
        crypt.cryptLogin(&src[14], 10);

        crypt.pack(src, length);
    }

    //make it fuzzy?

    s_uSerial++;
    src[1] = s_uSerial;


    int encLength = crypt.encrypt(dst + 2, src + 1, length - 1) + 2;

    if (code == 0xC1) {
        code = 0xC3;
    }

    //setting packet class
    dst[0] = code;
    //setting packet length
    dst[1] = static_cast<unsigned char>(encLength);

    if (params.size() == 3) {
        //head code
        params[1] = (uint8_t) dst[2];
        //sub code
        params[2] = (uint8_t) dst[3];
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

    extension.add("mu_encode_c3", mu_encode_c3, {
            Php::ByVal("data", Php::Type::String),
            Php::ByVal("head", Php::Type::Numeric),
            Php::ByVal("sub", Php::Type::Numeric)
    });

    return extension.module();
}
}