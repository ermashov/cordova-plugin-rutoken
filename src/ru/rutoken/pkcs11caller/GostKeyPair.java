package ru.rutoken.pkcs11caller;

import android.util.Base64;
import android.util.Log;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import ru.rutoken.pkcs11caller.exception.CertParsingException;
import ru.rutoken.pkcs11caller.exception.KeyNotFoundException;
import ru.rutoken.pkcs11caller.exception.KeyTypeNotSupported;
import ru.rutoken.pkcs11caller.exception.ObjectNotFoundException;
import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11caller.signature.Signature;
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import static ru.rutoken.pkcs11caller.Utils.findKey;
import static ru.rutoken.pkcs11caller.Utils.findObject;
import static ru.rutoken.pkcs11jna.RtPkcs11Constants.CKA_GOSTR3411_PARAMS;

public class GostKeyPair {

    private final byte[] mId;
    private final Signature.Type mKeyType;
    private final long mPubKeyHandle;

    private GostKeyPair(Pkcs11 pkcs11, long session, byte[] keyValue,  byte[] ckaId) throws Pkcs11CallerException {
        // уберём заголовок ключа (см ASN.1 Basic Encoding Rules)
        int pos = 2;
        if ((keyValue[1] & (byte) (1 << 7)) != 0)
            pos += keyValue[1] & (byte) (0xFF >> 1);
        keyValue = Arrays.copyOfRange(keyValue, pos, keyValue.length);

        CK_ATTRIBUTE[] pubKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        final NativeLongByReference keyClass =
                new NativeLongByReference(new NativeLong(Pkcs11Constants.CKO_PUBLIC_KEY));
        pubKeyTemplate[0].type = new NativeLong(Pkcs11Constants.CKA_CLASS);
        pubKeyTemplate[0].pValue = keyClass.getPointer();
        pubKeyTemplate[0].ulValueLen = new NativeLong(NativeLong.SIZE);

        /* OLD
        ByteBuffer valueBuffer = ByteBuffer.allocateDirect(keyValue.length);
        valueBuffer.put(keyValue);
        pubKeyTemplate[1].type = new NativeLong(Pkcs11Constants.CKA_VALUE);
        pubKeyTemplate[1].pValue = Native.getDirectBufferPointer(valueBuffer);
        pubKeyTemplate[1].ulValueLen = new NativeLong(keyValue.length);
        */

        ByteBuffer valueBuffer = ByteBuffer.allocateDirect(ckaId.length);
        valueBuffer.put(ckaId);
        pubKeyTemplate[1].type = new NativeLong(Pkcs11Constants.CKA_ID);
        pubKeyTemplate[1].pValue = Native.getDirectBufferPointer(valueBuffer);
        pubKeyTemplate[1].ulValueLen = new NativeLong(ckaId.length);

        try {
            mPubKeyHandle = findObject(pkcs11, session, pubKeyTemplate);
        } catch (ObjectNotFoundException e) {
            throw new KeyNotFoundException();
        }

        mKeyType = getKeyType(session, mPubKeyHandle, pkcs11);

        CK_ATTRIBUTE[] idTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(1);
        idTemplate[0].type = new NativeLong(Pkcs11Constants.CKA_ID);

        NativeLong rv = pkcs11.C_GetAttributeValue(new NativeLong(session), new NativeLong(mPubKeyHandle),
                idTemplate, new NativeLong(idTemplate.length));
        Pkcs11Exception.throwIfNotOk(rv);

        idTemplate[0].pValue = new Memory(idTemplate[0].ulValueLen.longValue());

        rv = pkcs11.C_GetAttributeValue(new NativeLong(session), new NativeLong(mPubKeyHandle),
                idTemplate, new NativeLong(idTemplate.length));
        Pkcs11Exception.throwIfNotOk(rv);

        mId = idTemplate[0].pValue.getByteArray(0, idTemplate[0].ulValueLen.intValue());

    }

    public static GostKeyPair getGostKeyPairByCertificate(Pkcs11 pkcs11, long session, X509CertificateHolder certificateHolder,  byte[] ckaId)
            throws Pkcs11CallerException {
        try {
            SubjectPublicKeyInfo publicKeyInfo = certificateHolder.getSubjectPublicKeyInfo();
            final byte[] keyValue = publicKeyInfo.parsePublicKey().getEncoded();
            return new GostKeyPair(pkcs11, session, keyValue, ckaId);
        } catch (IOException exception) {
            throw new CertParsingException();
        }

    }

    public Signature.Type getKeyType(long session, long pubKeyHandle, Pkcs11 pkcs11)
            throws Pkcs11Exception, KeyTypeNotSupported {
        CK_ATTRIBUTE[] publicKeyMechanismTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(1);

        //Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN
        publicKeyMechanismTemplate[0].type = new NativeLong(CKA_GOSTR3411_PARAMS);
        publicKeyMechanismTemplate[0].pValue = Pointer.NULL;
        publicKeyMechanismTemplate[0].ulValueLen = new NativeLong(0);

        try {

            NativeLong rv = pkcs11.C_GetAttributeValue(new NativeLong(session), new NativeLong(pubKeyHandle),
                    publicKeyMechanismTemplate, new NativeLong(1));
            Pkcs11Exception.throwIfNotOk(rv);

            ByteBuffer mechanismTypeValueBuffer =
                    ByteBuffer.allocateDirect(publicKeyMechanismTemplate[0].ulValueLen.intValue());
            publicKeyMechanismTemplate[0].pValue = Native.getDirectBufferPointer(mechanismTypeValueBuffer);

            rv = pkcs11.C_GetAttributeValue(new NativeLong(session), new NativeLong(pubKeyHandle),
                    publicKeyMechanismTemplate, new NativeLong(1));
            Pkcs11Exception.throwIfNotOk(rv);

            final byte[] parametersGostR3411 = publicKeyMechanismTemplate[0].pValue
                    .getByteArray(0, publicKeyMechanismTemplate[0].ulValueLen.intValue());

            if (Arrays.equals(parametersGostR3411, GostOids.OID_3411_1994))
                return Signature.Type.GOSTR3410_2001;
            else if (Arrays.equals(parametersGostR3411, GostOids.OID_3411_2012_256))
                return Signature.Type.GOSTR3410_2012_256;
            else if (Arrays.equals(parametersGostR3411, GostOids.OID_3411_2012_512))
                return Signature.Type.GOSTR3410_2012_512;
            else throw new KeyTypeNotSupported();

        }catch (Exception e){

            Log.v("ExceptiongetMessage + ", e.getMessage());
            return Signature.Type.RSA;

            /*
             else if (Arrays.equals(parametersGostR3411, GostOids.OID_3411_2012_512))
                return Signature.Type.RSA;
             */
            //throw new KeyTypeNotSupported();
        }


    }

    public long getPrivateKeyHandle(Pkcs11 pkcs11, long session)
            throws Pkcs11CallerException {

        long privateKeyHandle  = findKey(pkcs11, session, mId, true);

        return privateKeyHandle;
    }
    public long getPubKeyHandle(){
        return mPubKeyHandle;
    }

    public Signature.Type getKeyType() {
        return mKeyType;
    }
}
