/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.pkcs11caller;

import android.util.Log;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputDecryptor;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;

public class RsaKeyTransEnvelopedRecipient implements KeyTransRecipient {
    private final NativeLong mSessionHandle;
    private final long mKeyHandle;
    private final byte[] mIv;

    public RsaKeyTransEnvelopedRecipient(NativeLong sessionHandle, long keyHandle, byte[] iv) {
        mSessionHandle = sessionHandle;
        mKeyHandle = keyHandle;
        mIv = iv;
    }



    @Override
    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
            throws CMSException {
        try {

           /* //encryptedContentKey
            String data = "";
            try{
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(mKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey =  kf.generatePrivate(spec);

                Cipher rsa;
                rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.DECRYPT_MODE, privateKey);

                byte[] utf8 = rsa.doFinal(encryptedContentKey);

                data =  new String(utf8, "UTF8");

            }catch (Exception e){}


            Log.v("data", data);*/


            Pkcs11 pkcs11 = RtPkcs11Library.getInstance();

            NativeLong rv = pkcs11.C_DecryptInit(mSessionHandle, new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_RSA_PKCS), null, new NativeLong(0)), new NativeLong(mKeyHandle));
            Pkcs11Exception.throwIfNotOk(rv);

            NativeLongByReference decryptedDataSize = new NativeLongByReference(new NativeLong(8));

            rv = pkcs11.C_Decrypt(mSessionHandle, encryptedContentKey, new NativeLong(encryptedContentKey.length), null, decryptedDataSize);
            Pkcs11Exception.throwIfNotOk(rv);

            byte[] decryptedData = new byte[decryptedDataSize.getValue().intValue()];
            //byte[] decryptedData = new byte[8];
            rv = pkcs11.C_Decrypt(mSessionHandle, encryptedContentKey, new NativeLong(encryptedContentKey.length), decryptedData, decryptedDataSize);
            Pkcs11Exception.throwIfNotOk(rv);

            //final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            final Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
            IvParameterSpec ivspec = new IvParameterSpec(mIv);
            SecretKey key = new SecretKeySpec(decryptedData, 0, decryptedData.length, "DES");
            c.init(Cipher.DECRYPT_MODE, key, ivspec);

            return new RecipientOperator(new InputDecryptor()
            {
                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return contentEncryptionAlgorithm;
                }

                public InputStream getInputStream(InputStream dataIn)
                {
                    return new CipherInputStream(dataIn, c);
                }
            });
        } catch (Pkcs11Exception | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CMSException("CMS decrypt error", e);
        }
    }
}
