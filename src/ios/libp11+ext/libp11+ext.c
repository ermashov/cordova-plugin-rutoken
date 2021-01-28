//
//  libp11+ext.c
//  rutoken-swift
//
//  Created by Boris Bengus on 26.01.2021.
//

#include "libp11+ext.h"
#include "libp11-int.h"
#include <string.h>

/*
 * Костыль. Эти методы приватные в самой libp11 и находятся в p11_slot.c
 * как статические функции и не представлены в заголовочном файле.
 * Они требуются когда необходимо переинициализировать конкретный слот после C_WaitForSlotEvent.
 *
 * Имплементация в конце файла.
 */
static int pkcs11_init_slot(PKCS11_CTX *, PKCS11_SLOT *, CK_SLOT_ID);
static void pkcs11_release_slot(PKCS11_CTX *, PKCS11_SLOT *);
static int pkcs11_check_token(PKCS11_CTX *, PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

int PKCS11_wait_for_slot_event(PKCS11_CTX * ctx,
                               unsigned long * slot_id)
{
    if (check_fork(ctx) < 0)
        return -1;
    
    PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
    CK_RV rv;
    
    rv = cpriv->method->C_WaitForSlotEvent(0, slot_id, NULL_PTR); //(FALSE, NULL_PTR, &nslots);
    if (rv) { //CKR_CRYPTOKI_NOT_INITIALIZED
//        C_UnloadModule(cpriv->handle);
//        cpriv->handle = NULL;
//        CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
        return -1;
    }
//    CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);

    return 0;
}

int PKCS11_reinit_slot(PKCS11_CTX *ctx,
                       PKCS11_SLOT *slots,
                       unsigned int nslots,
                       unsigned long slot_id)
{
    if (check_fork(ctx) < 0)
        return -1;
    
    unsigned int i, foundOffset = -1;
    for (i=0; i < nslots; i++) {
        if (PKCS11_get_slotid_from_slot(&slots[i]) == slot_id) {
            foundOffset = i;
            break;
        }
    }
    
    // не нашли слот с нужным айди для переинициализации
    if (foundOffset == -1)
        return -1;
    
    // освободим только 1 слот по нужному оффсету
    pkcs11_release_slot(ctx, &slots[foundOffset]);
    if (pkcs11_init_slot(ctx, &slots[foundOffset], slot_id)) {
        return -1;
    }
    
    return 0;
}

/*
 * Helper functions
 */
static int pkcs11_init_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot, CK_SLOT_ID id)
{
    PKCS11_SLOT_private *spriv;
    CK_SLOT_INFO info;
    int rv;

    rv = CRYPTOKI_call(ctx, C_GetSlotInfo(id, &info));
    CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_SLOT, rv);

    spriv = OPENSSL_malloc(sizeof(PKCS11_SLOT_private));
    if (!spriv)
        return -1;
    memset(spriv, 0, sizeof(PKCS11_SLOT_private));

    spriv->parent = ctx;
    spriv->id = id;
    spriv->forkid = PRIVCTX(ctx)->forkid;
    spriv->prev_rw = 0;
    spriv->prev_pin = NULL;
    spriv->prev_so = 0;

    slot->description = PKCS11_DUP(info.slotDescription);
    slot->manufacturer = PKCS11_DUP(info.manufacturerID);
    slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;
    slot->_private = spriv;

    if ((info.flags & CKF_TOKEN_PRESENT) && pkcs11_check_token(ctx, slot))
        return -1;

    return 0;
}

static void pkcs11_release_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
    PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

    if (spriv) {
        if (spriv->prev_pin) {
            OPENSSL_cleanse(spriv->prev_pin, strlen(spriv->prev_pin));
            OPENSSL_free(spriv->prev_pin);
        }
        CRYPTOKI_call(ctx, C_CloseAllSessions(spriv->id));
    }
    OPENSSL_free(slot->_private);
    OPENSSL_free(slot->description);
    OPENSSL_free(slot->manufacturer);
    if (slot->token) {
        pkcs11_destroy_token(slot->token);
        OPENSSL_free(slot->token);
    }

    memset(slot, 0, sizeof(*slot));
}

static int pkcs11_check_token(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
    PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
    PKCS11_TOKEN_private *tpriv;
    CK_TOKEN_INFO info;
    int rv;

    if (slot->token) {
        pkcs11_destroy_token(slot->token);
    } else {
        slot->token = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
        if (!slot->token)
            return -1;
        memset(slot->token, 0, sizeof(PKCS11_TOKEN));
    }

    rv = CRYPTOKI_call(ctx, C_GetTokenInfo(spriv->id, &info));
    if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED) {
        OPENSSL_free(slot->token);
        slot->token = NULL;
        return 0;
    }
    CRYPTOKI_checkerr(CKR_F_PKCS11_CHECK_TOKEN, rv);

    /* We have a token */
    tpriv = OPENSSL_malloc(sizeof(PKCS11_TOKEN_private));
    if (!tpriv)
        return -1;
    memset(tpriv, 0, sizeof(PKCS11_TOKEN_private));
    tpriv->parent = slot;
    tpriv->prv.keys = NULL;
    tpriv->prv.num = 0;
    tpriv->pub.keys = NULL;
    tpriv->pub.num = 0;
    tpriv->ncerts = 0;

    slot->token->label = PKCS11_DUP(info.label);
    slot->token->manufacturer = PKCS11_DUP(info.manufacturerID);
    slot->token->model = PKCS11_DUP(info.model);
    slot->token->serialnr = PKCS11_DUP(info.serialNumber);
    slot->token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
    slot->token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
    slot->token->secureLogin = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
    slot->token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
    slot->token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
    slot->token->hasRng = (info.flags & CKF_RNG) ? 1 : 0;
    slot->token->userPinCountLow = (info.flags & CKF_USER_PIN_COUNT_LOW) ? 1 : 0;
    slot->token->userPinFinalTry = (info.flags & CKF_USER_PIN_FINAL_TRY) ? 1 : 0;
    slot->token->userPinLocked = (info.flags & CKF_USER_PIN_LOCKED) ? 1 : 0;
    slot->token->userPinToBeChanged = (info.flags & CKF_USER_PIN_TO_BE_CHANGED) ? 1 : 0;
    slot->token->soPinCountLow = (info.flags & CKF_SO_PIN_COUNT_LOW) ? 1 : 0;
    slot->token->soPinFinalTry = (info.flags & CKF_SO_PIN_FINAL_TRY) ? 1 : 0;
    slot->token->soPinLocked = (info.flags & CKF_SO_PIN_LOCKED) ? 1 : 0;
    slot->token->soPinToBeChanged = (info.flags & CKF_SO_PIN_TO_BE_CHANGED) ? 1 : 0;
    slot->token->_private = tpriv;

    return 0;
}

static void pkcs11_destroy_token(PKCS11_TOKEN *token)
{
    pkcs11_destroy_keys(token, CKO_PRIVATE_KEY);
    pkcs11_destroy_keys(token, CKO_PUBLIC_KEY);
    pkcs11_destroy_certs(token);

    OPENSSL_free(token->label);
    OPENSSL_free(token->manufacturer);
    OPENSSL_free(token->model);
    OPENSSL_free(token->serialnr);
    OPENSSL_free(token->_private);
    memset(token, 0, sizeof(*token));
}
