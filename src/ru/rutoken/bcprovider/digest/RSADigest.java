package ru.rutoken.bcprovider.digest;

import android.util.Log;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

class RSADigest extends Pkcs11Digest {

    RSADigest(Pkcs11 pkcs11, long sessionHandle) {
        super(pkcs11, sessionHandle, Pkcs11Constants.CKM_SHA_1);
    }

    @Override
    public Type getType() {
        return Type.RSA;
    }

    @Override
    public String getAlgorithmName() {
        return "PKCS11-RSA";
    }

    @Override
    public int getDigestSize() {
        return 64;
    }
}
