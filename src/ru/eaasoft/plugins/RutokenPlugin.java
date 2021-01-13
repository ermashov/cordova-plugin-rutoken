package ru.eaasoft.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEncryptedData;
import org.bouncycastle.cms.CMSEncryptedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.json.JSONArray;

import android.util.Base64;
import android.util.Log;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

import org.json.JSONObject;

import android.content.Context;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


import ru.rutoken.bcprovider.CmsSigner;
import ru.rutoken.pkcs11caller.Certificate;
import ru.rutoken.pkcs11caller.CertificateAndGostKeyPair;
import ru.rutoken.pkcs11caller.CertificateAndKeyPair;
import ru.rutoken.pkcs11caller.GostKeyPair;
import ru.rutoken.pkcs11caller.KeyPair;
import ru.rutoken.pkcs11caller.Pkcs11Result;
import ru.rutoken.pkcs11caller.RtPkcs11Library;
//import ru.rutoken.pkcs11caller.TokenManagerEvent;
//import ru.rutoken.pkcs11caller.SlotEventThread;
import ru.rutoken.pkcs11caller.Utils;
import ru.rutoken.pkcs11caller.exception.GeneralErrorException;
import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.CK_SLOT_INFO;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import ru.rutoken.pkcs11caller.Token;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_ADDED;
//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_REMOVED;

//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_EVENT_THREAD_FAILED;

public class RutokenPlugin extends CordovaPlugin {

    private String KeyStoreType = "Aktiv Rutoken ECP BT 1";

    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

    private String mPin = "15111989";

    public static final String NO_TOKEN = "";
    private String mTokenSerial = NO_TOKEN;
    public static CordovaWebView gWebView;

    public RutokenPlugin() {}

    public void pluginInitialize() {
        Log.d("CryptoproPlugin", "==> af ________ CryptoproPlugin pluginInitialize");
    }

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        gWebView = webView;
        Log.d("CryptoproPlugin", "==> af ________ CryptoproPlugin initialize");
        try {
            NativeLong rv;
            CK_C_INITIALIZE_ARGS initializeArgs = new CK_C_INITIALIZE_ARGS(null, null,
                    null, null, new NativeLong(Pkcs11Constants.CKF_OS_LOCKING_OK), null);
            rv = RtPkcs11Library.getInstance().C_Initialize(initializeArgs);
            Pkcs11Exception.throwIfNotOk(rv);
        } catch (Exception e) {
            Log.v(getClass().getName(), e.getMessage());
        }
    }

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        Context context = this.cordova.getActivity().getApplicationContext();

        if (action.equals("getTokens")) {
            try {
                NativeLong rv;
                NativeLongByReference slotCount = new NativeLongByReference(new NativeLong(0));
                rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_FALSE, null, slotCount);
                Pkcs11Exception.throwIfNotOk(rv);
                NativeLong[] slotIds = new NativeLong[slotCount.getValue().intValue()];
                rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_TRUE, slotIds, slotCount);
                Pkcs11Exception.throwIfNotOk(rv);
                JSONArray jsonArrResult = new JSONArray();

                for (int i = 0; i != slotCount.getValue().intValue(); ++i) {
                    //Log.v(getClass().getName(), slotIds[0].toString());
                    JSONObject jsonObjResult = new JSONObject();
                    CK_SLOT_INFO slotInfo = new CK_SLOT_INFO();
                    NativeLong rvl;

                    rvl = RtPkcs11Library.getInstance().C_GetSlotInfo(slotIds[i], slotInfo);
                    Pkcs11Exception.throwIfNotOk(rvl);

                    jsonObjResult.put("slotId", slotIds[i].toString());

                    final CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
                    Pkcs11Exception.throwIfNotOk(
                            RtPkcs11Library.getInstance().C_GetTokenInfo(slotIds[0], tokenInfo));

                    String mLabel = Utils.removeTrailingSpaces(tokenInfo.label);
                    String mModel = Utils.removeTrailingSpaces(tokenInfo.model);
                    String mSerialNumber = Utils.removeTrailingSpaces(tokenInfo.serialNumber);
                    long decSerial = Long.parseLong(mSerialNumber, 16);
                    String decSerialString = String.valueOf(decSerial);
                    String mShortDecSerialNumber = String.valueOf(decSerial % 100000);

                    jsonObjResult.put("label", mLabel);
                    jsonObjResult.put("model", mModel);
                    jsonObjResult.put("serialNumber", mSerialNumber);
                    jsonObjResult.put("decSerial", decSerialString);
                    jsonObjResult.put("shortDecSerialNumber", mShortDecSerialNumber);

                    jsonArrResult.put(jsonObjResult);
                }

                callbackContext.success(jsonArrResult.toString());
                return true;

            } catch (Exception e) {
                callbackContext.error("token error ex.");
                return false;
            }

        }else if(action.equals("waitForSlotEvent")){

            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {

                    while (!Thread.currentThread().isInterrupted()) {

                        NativeLongByReference slotId = new NativeLongByReference();
                        NativeLong rv;
                        rv = RtPkcs11Library.getInstance().C_WaitForSlotEvent(new NativeLong(0), slotId, null);

                        if (rv.longValue() == Pkcs11Constants.CKR_CRYPTOKI_NOT_INITIALIZED) {
                            Log.d("waitForSlotEvent", "Exit " + slotId.getValue().toString());
                            callbackContext.error("Token CKR_CRYPTOKI_NOT_INITIALIZED");
                        }

                        try {
                            String jsonResult = "";

                            Pkcs11Exception.throwIfNotOk(rv);
                            Log.d("waitForSlotEvent", "find slot id" + slotId.getValue().toString());

                            CK_SLOT_INFO slotInfo = new CK_SLOT_INFO();
                            NativeLong rvl;

                            rvl = RtPkcs11Library.getInstance().C_GetSlotInfo(slotId.getValue(), slotInfo);
                            Pkcs11Exception.throwIfNotOk(rvl);

                            JSONObject jsonObjResult = new JSONObject();
                            JSONObject jsonObjTokenInfo = new JSONObject();

                            jsonObjTokenInfo.put("slotId", slotId.getValue().toString());

                            if ((Pkcs11Constants.CKF_TOKEN_PRESENT & slotInfo.flags.longValue()) != 0x00) {

                                final CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
                                Pkcs11Exception.throwIfNotOk(
                                        RtPkcs11Library.getInstance().C_GetTokenInfo(slotId.getValue(), tokenInfo));

                                String mLabel = Utils.removeTrailingSpaces(tokenInfo.label);
                                String mModel = Utils.removeTrailingSpaces(tokenInfo.model);
                                String mSerialNumber = Utils.removeTrailingSpaces(tokenInfo.serialNumber);
                                long decSerial = Long.parseLong(mSerialNumber, 16);
                                String decSerialString = String.valueOf(decSerial);
                                String mShortDecSerialNumber = String.valueOf(decSerial % 100000);

                                jsonObjTokenInfo.put("label", mLabel);
                                jsonObjTokenInfo.put("model", mModel);
                                jsonObjTokenInfo.put("serialNumber", mSerialNumber);
                                jsonObjTokenInfo.put("decSerial", decSerialString);
                                jsonObjTokenInfo.put("shortDecSerialNumber", mShortDecSerialNumber);
                                jsonObjResult.put("event", "add");
                                Log.d("waitForSlotEvent", "add");
                            } else {
                                jsonObjResult.put("event", "remove");
                                Log.d("waitForSlotEvent", "remove");
                            }
                            jsonObjResult.put("tokenInfo", jsonObjTokenInfo);

                            jsonResult = jsonObjResult.toString();

                            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, jsonResult);
                            pluginResult.setKeepCallback(true);
                            callbackContext.sendPluginResult(pluginResult);

                        } catch (Exception e) {
                            callbackContext.error("slot error");
                        }
                    }
                }
            });

            return true;

        }else if(action.equals("getCertificates")) {
            try {
                NativeLong slotId = new NativeLong(args.getInt(0));
                NativeLong session = openSession(slotId);

                final HashMap<String, CertificateAndGostKeyPair> mCertificateGostMap = new HashMap<>();

                Certificate.CertificateCategory[] supportedCategories = {Certificate.CertificateCategory.UNSPECIFIED, Certificate.CertificateCategory.USER};

                for (Certificate.CertificateCategory category : supportedCategories) {
                    Map<String, CertificateAndGostKeyPair> certMap =  getCertificatesWithCategoryGost(category, session);
                    mCertificateGostMap.putAll(certMap);
                }

                JSONArray jsonArrResult = new JSONArray();

                for (Map.Entry<String, CertificateAndGostKeyPair> entry: mCertificateGostMap.entrySet()){

                    JSONObject jsonObject = new JSONObject();

                    jsonObject.put("Fingerprint",  entry.getKey());
                    jsonObject.put("CkaId",  new String(entry.getValue().getCertificate().getCkaId()));

                    JSONObject jsonObjectIssuer = new JSONObject();
                    X500NameStyle x500NameStyle = RFC4519Style.INSTANCE;
                    X500Name x500name =  entry.getValue().getCertificate().getCertificateHolder().getIssuer();
                    RDN[] rdns = x500name.getRDNs();
                    for ( RDN rdn : rdns ) {
                        for ( AttributeTypeAndValue attribute : rdn.getTypesAndValues() ) {
                            String attrName = x500NameStyle.oidToDisplayName( attribute.getType() );
                            if(attrName != null && attrName.length() > 0)
                                jsonObjectIssuer.put( attrName.toUpperCase(),  attribute.getValue());
                        }
                    }
                    jsonObject.put("Issuer",  jsonObjectIssuer);

                    JSONObject jsonObjectSubject = new JSONObject();
                    x500NameStyle = RFC4519Style.INSTANCE;
                    x500name =  entry.getValue().getCertificate().getCertificateHolder().getSubject();
                    rdns = x500name.getRDNs();
                    for ( RDN rdn : rdns ) {
                        for ( AttributeTypeAndValue attribute : rdn.getTypesAndValues() ) {
                            String attrName = x500NameStyle.oidToDisplayName( attribute.getType() );
                            if(attrName != null && attrName.length() > 0)
                                jsonObjectSubject.put( attrName.toUpperCase(),  attribute.getValue());
                        }
                    }

                    jsonObject.put("Subject",  jsonObjectSubject);
                    jsonObject.put("SerialNumber", entry.getValue().getCertificate().getCertificateHolder().getSerialNumber().toString(16).toUpperCase());
                    jsonArrResult.put(jsonObject);
                }

                closeSession(session);

                callbackContext.success(jsonArrResult.toString());
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }else if(action.equals("cmsSign")){
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {
                NativeLong slotId = new NativeLong(args.getInt(0));
                String pin = args.getString(1);
                String ckaId = args.getString(2);
                String pData = args.getString(3);

                String pinToUse = pin.length() > 0 ? pin : "";

                NativeLong session = openSession(slotId);

                NativeLong rvcl = mRtPkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);

                CertificateAndGostKeyPair cert = getCertificateByCkaId(ckaId, session);
                long hPrivateKey =  cert.getGostKeyPair().getPrivateKeyHandle(mRtPkcs11, session.longValue());
                byte[] data = pData.getBytes();
                final CmsSigner signer = new CmsSigner(cert.getGostKeyPair().getKeyType(), session.longValue());
                try (OutputStream stream = signer.initSignature(hPrivateKey, cert.getCertificate().getCertificateHolder(), true)) {
                    stream.write(data);
                } catch (IOException e) {
                    callbackContext.error(e.getMessage());
                }

                mRtPkcs11.C_Logout(session);
                closeSession(session);
                callbackContext.success( Base64.encodeToString(signer.finishSignature(), Base64.NO_WRAP));
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }else if(action.equals("cmsEncrypt")){
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {
                NativeLong slotId = new NativeLong(args.getInt(0));
                String pin = args.getString(1);
                String ckaId = args.getString(2);
                String pData = args.getString(3);

                String pinToUse = pin.length() > 0 ? pin : "";

                NativeLong session = openSession(slotId);

                NativeLong rvcl = mRtPkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);

                CertificateAndGostKeyPair cert = getCertificateByCkaId(ckaId, session);
                long hPubKey = cert.getGostKeyPair().getPubKeyHandle();

                CK_MECHANISM ckm = new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_RSA_PKCS),null, new NativeLong(0));
                NativeLong rvE = mRtPkcs11.C_EncryptInit(session, ckm, new NativeLong(hPubKey));
                Pkcs11Exception.throwIfNotOk(rvE);

                byte[] pbtData = pData.getBytes();
                final NativeLongByReference ulEncryptedDataSize = new NativeLongByReference();
                rvE = mRtPkcs11.C_Encrypt(session, pbtData,  new NativeLong(pbtData.length), null, ulEncryptedDataSize);
                Pkcs11Exception.throwIfNotOk(rvE);

                final byte[] pbtEncryptedData = new byte[ulEncryptedDataSize.getValue().intValue()];
                rvE = mRtPkcs11.C_Encrypt(session, pbtData,  new NativeLong(pbtData.length), pbtEncryptedData, ulEncryptedDataSize);
                Pkcs11Exception.throwIfNotOk(rvE);

                mRtPkcs11.C_Logout(session);
                closeSession(session);

                callbackContext.success( Base64.encodeToString(pbtEncryptedData, Base64.NO_WRAP));
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }else if(action.equals("cmsDecrypt")){
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {
                NativeLong slotId = new NativeLong(args.getInt(0));
                String pin = args.getString(1);
                String ckaId = args.getString(2);
                String pData = args.getString(3);

                String pinToUse = pin.length() > 0 ? pin : "";

                NativeLong session = openSession(slotId);

                NativeLong rvcl = mRtPkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);

                CertificateAndGostKeyPair cert = getCertificateByCkaId(ckaId, session);
                long hPrivateKey =  cert.getGostKeyPair().getPrivateKeyHandle(mRtPkcs11, session.longValue());

                CK_MECHANISM ckm = new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_RSA_PKCS),null, new NativeLong(0));

                byte[] pbtEncryptedData = Base64.decode(pData, Base64.NO_WRAP);

                NativeLong rv = mRtPkcs11.C_DecryptInit(session, ckm, new NativeLong(hPrivateKey));
                Pkcs11Exception.throwIfNotOk(rv);

                final NativeLongByReference ulDecryptedDataSize = new NativeLongByReference();

                rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), null, ulDecryptedDataSize);
                Pkcs11Exception.throwIfNotOk(rv);

                final byte[] pbtDecryptedData = new byte[ulDecryptedDataSize.getValue().intValue()];
                rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), pbtDecryptedData, ulDecryptedDataSize);
                Pkcs11Exception.throwIfNotOk(rv);

                mRtPkcs11.C_Logout(session);
                closeSession(session);
                callbackContext.success(new String(pbtDecryptedData));
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }else if(action.equals("cmsDecrypts")){
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {
                NativeLong slotId = new NativeLong(args.getInt(0));
                String pin = args.getString(1);
                String ckaId = args.getString(2);
                String data = args.getString(3);
                String[] arData = data.split(",");

                String pinToUse = pin.length() > 0 ? pin : "";

                NativeLong session = openSession(slotId);

                NativeLong rvcl = mRtPkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);

                CertificateAndGostKeyPair cert = getCertificateByCkaId(ckaId, session);
                long hPrivateKey =  cert.getGostKeyPair().getPrivateKeyHandle(mRtPkcs11, session.longValue());

                CK_MECHANISM ckm = new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_RSA_PKCS),null, new NativeLong(0));


                String resultData = "";

                Log.v("Encrypt pData length", String.valueOf(arData.length));

                Integer i = 0;
                for (String pData : arData){

                    Log.v("Encrypt pData", pData);

                    byte[] pbtEncryptedData = Base64.decode(pData, Base64.NO_WRAP);

                    Log.v("Encrypt", "1");
                    NativeLong rv = mRtPkcs11.C_DecryptInit(session, ckm, new NativeLong(hPrivateKey));
                    Pkcs11Exception.throwIfNotOk(rv);

                    Log.v("Encrypt", "2");
                    final NativeLongByReference ulDecryptedDataSize = new NativeLongByReference();
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), null, ulDecryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);
                    Log.v("Encrypt", "3");
                    final byte[] pbtDecryptedData = new byte[ulDecryptedDataSize.getValue().intValue()];
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), pbtDecryptedData, ulDecryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);

                    Log.v("Encrypt", "end item");
                    resultData += (i > 0 ? ",":"") + Base64.encodeToString(pbtDecryptedData, Base64.NO_WRAP);
                    i++;
                }

                mRtPkcs11.C_Logout(session);
                closeSession(session);
                callbackContext.success(resultData);
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }

        callbackContext.error("method not found");
        return false;
    }

    private  void closeSession(NativeLong mSession){
        try {
            NativeLong rv = RtPkcs11Library.getInstance().C_CloseSession(mSession);
            Pkcs11Exception.throwIfNotOk(rv);
        } catch (Pkcs11CallerException e) {
            e.printStackTrace();
        }
    }

    private NativeLong openSession(NativeLong slotId) throws Pkcs11Exception {
        final NativeLongByReference session = new NativeLongByReference();
        final NativeLong rv = RtPkcs11Library.getInstance().C_OpenSession(
                slotId, new NativeLong(Pkcs11Constants.CKF_SERIAL_SESSION), null, null, session);

        return session.getValue();
    }

    private Map<String, CertificateAndGostKeyPair> getCertificatesWithCategoryGost(Certificate.CertificateCategory category,
                                                                                   NativeLong session)
            throws Pkcs11CallerException {

        RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();

        CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        NativeLongByReference certClass = new NativeLongByReference(new NativeLong(Pkcs11Constants.CKO_CERTIFICATE));
        template[0].type = new NativeLong(Pkcs11Constants.CKA_CLASS);
        template[0].pValue = certClass.getPointer();
        template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

        NativeLongByReference certCategory = new NativeLongByReference(new NativeLong(category.getValue()));
        template[1].type = new NativeLong(Pkcs11Constants.CKA_CERTIFICATE_CATEGORY);
        template[1].pValue = certCategory.getPointer();
        template[1].ulValueLen = new NativeLong(NativeLong.SIZE);

        NativeLong rv = mRtPkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
        Pkcs11Exception.throwIfNotOk(rv);

        NativeLong[] objects = new NativeLong[30];
        NativeLongByReference count = new NativeLongByReference(new NativeLong(objects.length));
        ArrayList<NativeLong> certs = new ArrayList<>();
        do {
            rv = mRtPkcs11.C_FindObjects(session, objects, new NativeLong(objects.length), count);
            if (rv.longValue() != Pkcs11Constants.CKR_OK) break;
            certs.addAll(Arrays.asList(objects).subList(0, count.getValue().intValue()));
        } while (count.getValue().longValue() == objects.length);
        NativeLong rv2 = mRtPkcs11.C_FindObjectsFinal(session);
        Pkcs11Exception.throwIfNotOk(rv);
        Pkcs11Exception.throwIfNotOk(rv2);

        HashMap<String, CertificateAndGostKeyPair> certificateMap = new HashMap<>();
        for (NativeLong c : certs) {
            try {
                Certificate cert = new Certificate(mRtPkcs11, session.longValue(), c.longValue());

                 GostKeyPair keyPair = GostKeyPair.getGostKeyPairByCertificate(mRtPkcs11,
                        session.longValue(), cert.getCertificateHolder(), cert.getCkaId());

                CertificateAndGostKeyPair cagKeyPair = new CertificateAndGostKeyPair(cert, keyPair);

               // long hPubKey = keyPair.getPubKeyHandle();

                if(new String(cert.getCkaId()).equals("190d26ca-3862-4c05-82e0-a0032882566e_E")){

                    /** fine work
                    Log.v("TAG", "C_DigestInit ========================================================");
                    CK_MECHANISM ckm = new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_SHA_1),null, new NativeLong(0));
                    rv = mRtPkcs11.C_DigestInit(session, ckm);
                    Pkcs11Exception.throwIfNotOk(rv);
                    Log.v("TAG", "C_DigestInit ok /////////////////////////////////////////////////////");
                    */

                    /** fine encrypt
                    CK_MECHANISM ckm = new CK_MECHANISM(new NativeLong(Pkcs11Constants.CKM_RSA_PKCS),null, new NativeLong(0));
                    NativeLong rvE = mRtPkcs11.C_EncryptInit(session, ckm, new NativeLong(hPubKey));
                    Pkcs11Exception.throwIfNotOk(rvE);
                    byte[] pbtData = "hello".getBytes();
                    final NativeLongByReference ulEncryptedDataSize = new NativeLongByReference();
                    rvE = mRtPkcs11.C_Encrypt(session, pbtData,  new NativeLong(pbtData.length), null, ulEncryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rvE);
                    final byte[] pbtEncryptedData = new byte[ulEncryptedDataSize.getValue().intValue()];
                    rvE = mRtPkcs11.C_Encrypt(session, pbtData,  new NativeLong(pbtData.length), pbtEncryptedData, ulEncryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rvE);
                    Log.v("EncryptedData", Base64.encodeToString(pbtEncryptedData, Base64.NO_WRAP));

                    rv = mRtPkcs11.C_DecryptInit(session, ckm, new NativeLong(hPrivateKey));
                    Pkcs11Exception.throwIfNotOk(rv);
                    final NativeLongByReference ulDecryptedDataSize = new NativeLongByReference();
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), null, ulEncryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);
                    final byte[] pbtDecryptedData = new byte[ulEncryptedDataSize.getValue().intValue()];
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), pbtEncryptedData, ulEncryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);
                    Log.v("TAG", "C_EncryptInit pbtEncryptedData " + new String(pbtEncryptedData));
                   // Log.v("TAG", "C_DecryptInit ok /////////////////////////////////////////////////////");
                 */
                }

                certificateMap.put(cert.fingerprint(), cagKeyPair);

            } catch (Pkcs11CallerException ignore) {
                Log.v("TAG ignore error", ignore.getMessage());
            }
        }
        return certificateMap;
    }

    private CertificateAndGostKeyPair getCertificateByCkaId(String ckaId, NativeLong session)  throws Pkcs11CallerException {
        CertificateAndGostKeyPair cagKeyPair = null;

        RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();

        CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        NativeLongByReference certClass = new NativeLongByReference(new NativeLong(Pkcs11Constants.CKO_CERTIFICATE));
        template[0].type = new NativeLong(Pkcs11Constants.CKA_CLASS);
        template[0].pValue = certClass.getPointer();
        template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

        byte[] bCkaId = ckaId.getBytes();
        ByteBuffer valueBuffer = ByteBuffer.allocateDirect(bCkaId.length);
        valueBuffer.put(bCkaId);
        template[1].type = new NativeLong(Pkcs11Constants.CKA_ID);
        template[1].pValue = Native.getDirectBufferPointer(valueBuffer);
        template[1].ulValueLen = new NativeLong(bCkaId.length);

        NativeLong rv = mRtPkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
        Pkcs11Exception.throwIfNotOk(rv);

        NativeLong[] objects = new NativeLong[1];
        NativeLongByReference count = new NativeLongByReference(new NativeLong(objects.length));
        rv = mRtPkcs11.C_FindObjects(session, objects, new NativeLong(objects.length), count);

        NativeLong rv2 = mRtPkcs11.C_FindObjectsFinal(session);

        Pkcs11Exception.throwIfNotOk(rv);
        Pkcs11Exception.throwIfNotOk(rv2);

        Certificate cert = new Certificate(mRtPkcs11, session.longValue(), objects[0].longValue());

        GostKeyPair keyPair = GostKeyPair.getGostKeyPairByCertificate(mRtPkcs11, session.longValue(), cert.getCertificateHolder(), cert.getCkaId());

        cagKeyPair = new CertificateAndGostKeyPair(cert, keyPair);

        return cagKeyPair;

    }


    @Override public void onDestroy () {
        Log.v("CryptoproPlugin","af ==> ______________ onStop");
        super.onDestroy();
        RtPkcs11Library.getInstance().C_Finalize(null);
    };

    /*
        for (String serial : TokenManager.getInstance().getTokenSerials()) {
            Log.v(getClass().getName(), "serial for");

            Log.v(getClass().getName(), serial);

            if (!mTokenSerial.equals(NO_TOKEN))
                break;
            //processConnectedToken(TokenManager.getInstance().getTokenBySerial(serial));

            Token  token =  TokenManager.getInstance().getTokenBySerial(serial);
            String tokenSerial = token.getSerialNumber();

            Log.v(getClass().getName(), tokenSerial);


            Set<String> certificateFingerprints = token.enumerateCertificates();

            Log.v(getClass().getName(), certificateFingerprints.toString());

            callbackContext.error("token list.");
            return false;
        }

        if (1 == 2) {
            callbackContext.error("Couldn't initialize CSP.");
            return false;
        }


        if (action.equals("getCertificates")) {
           // this.getCertificates(callbackContext);
            return true;
        }else if(action.equals("singCades")){
            try {

                return true;
            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        return false;*/

    /*
    private void processConnectedToken(@Nullable Token token) {
        if (token == null)
            return;
        String tokenSerial = token.getSerialNumber();
        Set<String> certificateFingerprints = token.enumerateCertificates();

        if (mDoWait) { // process wait token once
            do {
                if (certificateFingerprints.isEmpty()) break;

                if (!tokenSerial.equals(mWaitToken.getSerialNumber())) break;

                String certFingerprint = null;
                for (String fp : certificateFingerprints) {
                    if (fp.equals(mWaitCertificateFingerprint)) {
                        certFingerprint = fp;
                        break;
                    }
                }

                if (certFingerprint != null) {
                    mTokenSerial = tokenSerial;
                    mToken = token;
                    mCertificateFingerprint = certFingerprint;
                    if (mMainActivity != null)
                        mMainActivity.startPINActivity();
                    break;
                }
            } while (false);
        }

        if (mDoWait)
            // if the expected device was connected it was processed in the previous block
            resetWaitForToken();

        if (mTokenSerial.equals(NO_TOKEN)) {
            mTokenSerial = tokenSerial;
            mToken = token;
            if (certificateFingerprints.iterator().hasNext()) {
                mCertificateFingerprint = certificateFingerprints.iterator().next();
            } else {
                mCertificateFingerprint = NO_FINGERPRINT;
            }

            if (mMainActivity != null)
                mMainActivity.updateScreen();
        }
    }*/


    private void getCertificates(CallbackContext callbackContext) {

        String jsonCertificates = "";

        if(jsonCertificates.length() <= 0){
            callbackContext.error("not found cert or container");
        }else {
            callbackContext.success(jsonCertificates);
        }

    }
}

