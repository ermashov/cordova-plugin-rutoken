package ru.eaasoft.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;

import android.os.Build;
import android.util.Base64;
import android.util.Log;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import org.json.JSONObject;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.annotation.RequiresApi;
import ru.rutoken.bcprovider.CmsSigner;
import ru.rutoken.pkcs11caller.Certificate;
import ru.rutoken.pkcs11caller.CertificateAndGostKeyPair;
import ru.rutoken.pkcs11caller.GostKeyPair;
import ru.rutoken.pkcs11caller.RtPkcs11Library;
//import ru.rutoken.pkcs11caller.TokenManagerEvent;
//import ru.rutoken.pkcs11caller.SlotEventThread;
import ru.rutoken.pkcs11caller.Utils;
import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.CK_SLOT_INFO;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11caller.RsaKeyTransEnvelopedRecipient;


import ru.rutoken.pkcs11jna.RtPkcs11;

//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_ADDED;
//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_REMOVED;

//import static ru.rutoken.pkcs11caller.TokenManagerEvent.EventType.SLOT_EVENT_THREAD_FAILED;

public class RutokenPlugin extends CordovaPlugin {

    public static final String NO_TOKEN = "";
    private String mTokenSerial = NO_TOKEN;
    private NativeLong mSession;
    private HashMap<String, CertificateAndGostKeyPair> mCertificateGostMap = new HashMap<>();
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

        if (action.equals("init")) {
           try{
               NativeLong rv;
               NativeLongByReference slotCount = new NativeLongByReference(new NativeLong(0));
               rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_FALSE, null, slotCount);
               Pkcs11Exception.throwIfNotOk(rv);
               NativeLong[] slotIds = new NativeLong[slotCount.getValue().intValue()];
               rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_TRUE, slotIds, slotCount);
               Pkcs11Exception.throwIfNotOk(rv);
               mSession = openSession(slotIds[0]);
               callbackContext.success("ok");
               return true;
           }catch (Exception e){
               callbackContext.error(e.getMessage());
               return false;
           }
        }
        else if (action.equals("getTokens"))
        {
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

                if(slotIds.length > 0)
                    mSession = openSession(slotIds[0]);

                callbackContext.success(jsonArrResult.toString());
                return true;

            } catch (Exception e) {
                callbackContext.error("token error ex.");
                return false;
            }

        }
        else if(action.equals("waitForSlotEvent"))
        {

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
                                mSession = openSession(slotId.getValue());
                                Log.d("waitForSlotEvent", "add");
                            } else {
                                jsonObjResult.put("event", "remove");
                                //closeSession(mSession);
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

        }
        else if(action.equals("getCertificates"))
        {
            try {
                //NativeLong slotId = new NativeLong(args.getInt(0));
                //NativeLong session = openSession(slotId);
                NativeLong session = mSession;

                //final HashMap<String, CertificateAndGostKeyPair> mCertificateGostMap = new HashMap<>();

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

                    for (RDN emails : x500name.getRDNs(BCStyle.EmailAddress)) {
                        for (AttributeTypeAndValue emailAttr : emails.getTypesAndValues()) {
                            jsonObjectSubject.put("Email",  emailAttr.getValue());
                        }
                    }

                    rdns = x500name.getRDNs();
                    for ( RDN rdn : rdns ) {
                        for ( AttributeTypeAndValue attribute : rdn.getTypesAndValues() ) {
                            String attrName = x500NameStyle.oidToDisplayName( attribute.getType() );
                            if(attrName != null && attrName.length() > 0)
                                jsonObjectSubject.put( attrName.toUpperCase(),  attribute.getValue());
                        }
                    }
                    jsonObject.put("Subject",  jsonObjectSubject);
                    jsonObject.put("Pem",  entry.getValue().getCertificate().getCertificatePem());
                    jsonObject.put("SerialNumber", entry.getValue().getCertificate().getCertificateHolder().getSerialNumber().toString(16).toUpperCase());
                    jsonArrResult.put(jsonObject);
                }

                //closeSession(session);

                callbackContext.success(jsonArrResult.toString());
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        else if(action.equals("cmsSign"))
        {
            try {

                String ckaId = args.getString(0);
                String pData = args.getString(1);

                //NativeLong session = openSession(slotId);
                NativeLong session = mSession;

                CertificateAndGostKeyPair cert = null;
                Log.v("Cert", "1");
                for (Map.Entry<String, CertificateAndGostKeyPair> entry: mCertificateGostMap.entrySet()){
                    Log.v("ckaId item", new String(entry.getValue().getCertificate().getCkaId()));
                    if(new String(entry.getValue().getCertificate().getCkaId()).equals(ckaId)){
                        cert = entry.getValue();
                    }
                }
                Log.v("ckaId", ckaId);
                Log.v("Cert", "3");

                long hPrivateKey =  cert.getGostKeyPair().getPrivKeyHandle();

                byte[] data = pData.getBytes();
                final CmsSigner signer = new CmsSigner(cert.getGostKeyPair().getKeyType(), session.longValue());
                try (OutputStream stream = signer.initSignature(hPrivateKey, cert.getCertificate().getCertificateHolder(), true)) {
                    stream.write(data);
                } catch (IOException e) {
                    callbackContext.error(e.getMessage());
                }

                //closeSession(session);
                callbackContext.success( Base64.encodeToString(signer.finishSignature(), Base64.NO_WRAP));
                return true;

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        else if(action.equals("cmsEncrypt"))
        {

            try {

                //String hPubKey = args.getString(0);
                String CkaId = args.getString(0);
                String pData = args.getString(1);


                String hPubKey = "";

                Log.v("hPubKey", CkaId);

                for (Map.Entry<String, CertificateAndGostKeyPair> entry: mCertificateGostMap.entrySet()){
                    if(new String(entry.getValue().getCertificate().getCkaId()).equals(CkaId)){
                        hPubKey = entry.getValue().getCertificate().getCertificatePem();
                    }
                }

                Log.v("hPubKey", hPubKey);

                CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(Base64.decode(hPubKey, Base64.NO_WRAP)));
                cmsEnvelopedDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate));
                CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(new CMSProcessableByteArray(pData.getBytes()),
                        new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_CBC)
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build());

                callbackContext.success( Base64.encodeToString(cmsEnvelopedData.getEncoded(), Base64.NO_WRAP));

                return true;
                /*
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
                return true;*/

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        else if(action.equals("cmsDecrypt"))
        {
            //long m = System.currentTimeMillis();
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {
                //NativeLong slotId = new NativeLong(args.getInt(0));
                //String pin = args.getString(1);
                String ckaId = args.getString(0);
                String pData = args.getString(1);

                //Log.v("cmsDecrypt ", "Init");

                byte[] encryptedCms = Base64.decode(pData, Base64.NO_WRAP);

                //String pinToUse = pin.length() > 0 ? pin : "";

                //m = System.currentTimeMillis();

                //NativeLong session = openSession(slotId);
                NativeLong session = mSession;

                //System.out.println("openSession");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);


                //m = System.currentTimeMillis();
                /*NativeLong rvcl = mRtPkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);*/

                //System.out.println("C_Login");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);

                CertificateAndGostKeyPair cert = null;
                Log.v("Cert", "1");
                for (Map.Entry<String, CertificateAndGostKeyPair> entry: mCertificateGostMap.entrySet()){
                    if(new String(entry.getValue().getCertificate().getCkaId()).equals(ckaId)){
                        cert = entry.getValue();
                    }
                }
                Log.v("Cert", "3");

                //m = System.currentTimeMillis();
                //CertificateAndGostKeyPair cert = getCertificateByCkaId(ckaId, session);
                //long hPrivateKey =  cert.getGostKeyPair().getPrivateKeyHandle(mRtPkcs11, session.longValue());
                long hPrivateKey =  cert.getGostKeyPair().getPrivKeyHandle();
                byte[] hPubKey =  Base64.decode(cert.getCertificate().getCertificatePem(), Base64.NO_WRAP);

                //System.out.println("getCertificateByCkaId");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);

                //m = System.currentTimeMillis();
                Security.addProvider(new BouncyCastleProvider());
                X509Certificate recipientCertificate = new JcaX509CertificateConverter().
                        setProvider(BouncyCastleProvider.PROVIDER_NAME).
                        getCertificate(new X509CertificateHolder(hPubKey));
                List<X509Certificate> possibleRecipientsCertificates = Collections.singletonList(recipientCertificate);
                final CMSEnvelopedData cms = new CMSEnvelopedData(encryptedCms);
                RecipientInformationStore recipientsStore = cms.getRecipientInfos();
                byte[] params = cms.getEncryptionAlgParams();
                byte[] iv = Arrays.copyOfRange(params, 2, params.length);

                //System.out.println("BouncyCastleProvider");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);

                //m = System.currentTimeMillis();
                byte[] pbtDecryptedData = possibleRecipientsCertificates.stream()
                        .filter(possibleRecipientCert ->
                                !matchRecipients(recipientsStore, possibleRecipientCert).isEmpty())
                        .findAny()
                        .map(recipientCert -> {
                            try {
                                return matchRecipients(recipientsStore, recipientCert)
                                        .iterator().next()
                                        .getContent(new RsaKeyTransEnvelopedRecipient(session, hPrivateKey, iv));
                            } catch (CMSException e) {
                                throw new RuntimeException(e);
                            }
                        })
                        .orElseThrow(() -> new IllegalStateException("Corresponding RecipientInformation is absent"));

                //System.out.println("possibleRecipientsCertificates");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);

                //m = System.currentTimeMillis();
               // mRtPkcs11.C_Logout(session);
                //System.out.println("C_Logout");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);

                //m = System.currentTimeMillis();
                //closeSession(session);
                //System.out.println("C_Logout");
                //System.out.println((double) (System.currentTimeMillis() - m) / 1000);
                callbackContext.success(new String(pbtDecryptedData));
                return true;


                /*
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
                return true;*/

            }catch (Exception e){
                Log.v("Error", e.getMessage());
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        else if(action.equals("login"))
        {
            //long m = System.currentTimeMillis();
            RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();
            try {

                String pin = args.getString(0);
                //Log.v("cmsDecrypt ", "Init");

                String pinToUse = pin.length() > 0 ? pin : "";

                Log.v("Pin", pinToUse);
                NativeLong rvcl = mRtPkcs11.C_Login(mSession, new NativeLong(Pkcs11Constants.CKU_USER),
                        pinToUse.getBytes(), new NativeLong(pinToUse.length()));
                Pkcs11Exception.throwIfNotOk(rvcl);

                callbackContext.success("ok");
                return true;

            }catch (Exception e){
                Log.v("Error", e.getMessage());
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        else if(action.equals("cmsDecrypts"))
        {
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

                Integer i = 0;
                for (String pData : arData){

                    byte[] pbtEncryptedData = Base64.decode(pData, Base64.NO_WRAP);

                    NativeLong rv = mRtPkcs11.C_DecryptInit(session, ckm, new NativeLong(hPrivateKey));
                    Pkcs11Exception.throwIfNotOk(rv);

                    final NativeLongByReference ulDecryptedDataSize = new NativeLongByReference();
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), null, ulDecryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);

                    final byte[] pbtDecryptedData = new byte[ulDecryptedDataSize.getValue().intValue()];
                    rv = mRtPkcs11.C_Decrypt(session, pbtEncryptedData,  new NativeLong(pbtEncryptedData.length), pbtDecryptedData, ulDecryptedDataSize);
                    Pkcs11Exception.throwIfNotOk(rv);

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


    private Collection<RecipientInformation> matchRecipients(RecipientInformationStore recipientsStore, X509Certificate possibleRecipientCert) {
        return recipientsStore.getRecipients(new JceKeyTransRecipientId(possibleRecipientCert));
        //return (Collection<RecipientInformation>) recipientsStore.get(new JceKeyTransRecipientId(possibleRecipientCert));
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

}