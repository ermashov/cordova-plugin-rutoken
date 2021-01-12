package ru.rutoken.pkcs11caller.signature;

import android.util.Log;

import ru.rutoken.bcprovider.digest.Digest;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

class RSASignature extends AbstractSignature {

    RSASignature(Pkcs11 pkcs11, long sessionHandle) {
        super(pkcs11, sessionHandle);
    }

    @Override
    public byte[] sign(final byte[] data) throws Pkcs11Exception {
        return innerSign(makeMechanism(Pkcs11Constants.CKM_RSA_PKCS), data);
        //return innerSign(makeMechanism(RtPkcs11Constants.CKM_GOSTR3410_512), data);
    }

    @Override
    public Type getType() {
        return Type.RSA;
    }

    @Override
    public Digest.Type getDigestType() {
        return Digest.Type.RSA;
    }
}
