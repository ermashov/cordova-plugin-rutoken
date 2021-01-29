//
//  rutoken-swift-Bridging-Header.h
//  rutoken-swift
//
//  Created by Boris Bengus on 13.01.2021.
//

#ifndef rutoken_swift_Bridging_Header_h

/* модуль PKCS#11 от Рутокен */
#include <rtpkcs11ecp/rtpkcs11.h>
/* OpenSSL */
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/asn1.h>
//#include <openssl/asn1_locl.h>
/* Легковесная обертка над PKCS#11 и OpenSSL структурами */
#include "libp11.h"
/* Дополнительные функции, отсутствующие в libp11 */
#include "libp11+ext.h"

#define rutoken_swift_Bridging_Header_h


#endif /* rutoken_swift_Bridging_Header_h */
