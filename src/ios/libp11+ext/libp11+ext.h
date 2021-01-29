//
//  libp11+ext.h
//  rutoken-swift
//
//  Created by Boris Bengus on 26.01.2021.
//

#ifndef libp11_ext_h
#define libp11_ext_h

#include "libp11.h"

int PKCS11_wait_for_slot_event(PKCS11_CTX * ctx,
                               unsigned long * slot_id);

/*
 * Переинициализируем слот с конкретным айди. Предыдущий инстаци будет освобожден.
 * Связанные ключи и сертификаты с токеном на слоте так же будут освобождены.
 */
int PKCS11_reinit_slot(PKCS11_CTX *ctx,
                       PKCS11_SLOT *slots,
                       unsigned int nslots,
                       unsigned long slot_id);

#endif /* libp11_ext_h */
