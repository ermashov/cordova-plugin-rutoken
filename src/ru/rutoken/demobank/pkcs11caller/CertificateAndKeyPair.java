package ru.rutoken.demobank.pkcs11caller;

import java.util.Objects;

public class CertificateAndKeyPair {
    private final Certificate mCertificate;
    private final KeyPair mKeyPair;

    public CertificateAndKeyPair(Certificate certificate, KeyPair keyPair) {
        mCertificate = Objects.requireNonNull(certificate);
        mKeyPair = Objects.requireNonNull(keyPair);
    }

    Certificate getCertificate() {
        return mCertificate;
    }

    KeyPair getKeyPair() {
        return mKeyPair;
    }
}
