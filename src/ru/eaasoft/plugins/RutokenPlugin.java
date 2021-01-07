package ru.eaasoft.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;

import android.util.Log;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import org.json.JSONObject;

import android.content.Context;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


import ru.rutoken.demobank.pkcs11caller.Certificate;
import ru.rutoken.demobank.pkcs11caller.CertificateAndKeyPair;
import ru.rutoken.demobank.pkcs11caller.GostKeyPair;
import ru.rutoken.demobank.pkcs11caller.KeyPair;
import ru.rutoken.demobank.pkcs11caller.RtPkcs11Library;
//import ru.rutoken.demobank.pkcs11caller.TokenManagerEvent;
//import ru.rutoken.demobank.pkcs11caller.SlotEventThread;
import ru.rutoken.demobank.pkcs11caller.Utils;
import ru.rutoken.demobank.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.demobank.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS;
import ru.rutoken.pkcs11jna.CK_SLOT_INFO;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import ru.rutoken.demobank.pkcs11caller.Token;
import ru.rutoken.pkcs11jna.RtPkcs11;

//import static ru.rutoken.demobank.pkcs11caller.TokenManagerEvent.EventType.SLOT_ADDED;
//import static ru.rutoken.demobank.pkcs11caller.TokenManagerEvent.EventType.SLOT_REMOVED;

//import static ru.rutoken.demobank.pkcs11caller.TokenManagerEvent.EventType.SLOT_EVENT_THREAD_FAILED;

public class RutokenPlugin extends CordovaPlugin {

    private String KeyStoreType = "Aktiv Rutoken ECP BT 1";

    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

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
            Log.v("V","in 1");
            CK_C_INITIALIZE_ARGS initializeArgs = new CK_C_INITIALIZE_ARGS(null, null,
                    null, null, new NativeLong(Pkcs11Constants.CKF_OS_LOCKING_OK), null);
            rv = RtPkcs11Library.getInstance().C_Initialize(initializeArgs);
            Pkcs11Exception.throwIfNotOk(rv);
        } catch (Exception e) {
            Log.v(getClass().getName(),"not init");
            Log.v(getClass().getName(), e.getMessage());
        }
    }

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        Context context = this.cordova.getActivity().getApplicationContext();

        if (action.equals("getTokens")) {
            try {
                NativeLong rv;

                Log.v("V","in 2");

                NativeLongByReference slotCount = new NativeLongByReference(new NativeLong(0));
                rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_FALSE, null, slotCount);
                Pkcs11Exception.throwIfNotOk(rv);

                Log.v("V","in 3");

                NativeLong[] slotIds = new NativeLong[slotCount.getValue().intValue()];
                rv = RtPkcs11Library.getInstance().C_GetSlotList(Pkcs11Constants.CK_TRUE, slotIds, slotCount);
                Pkcs11Exception.throwIfNotOk(rv);

                Log.v("V","in 4");

                JSONArray jsonArrResult = new JSONArray();

                for (int i = 0; i != slotCount.getValue().intValue(); ++i) {
                    Log.v(getClass().getName(), "yeee find");
                    Log.v(getClass().getName(), slotIds[0].toString());

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

                /*if(slotIds.length <= 0 || slotCount.getValue().intValue() <= 0){
                    callbackContext.error("Token not found");
                    return false;
                }*/

                callbackContext.success(jsonArrResult.toString());
                return true;

            } catch (Exception e) {
                callbackContext.error("token error ex.");
                Log.v(getClass().getName(),"Exception");
                Log.v(getClass().getName(), e.getMessage());
                return false;
                //TokenManager.getInstance().postEvent(new TokenManagerEvent(SLOT_EVENT_THREAD_FAILED));
            }

            //callbackContext.error("Token not found");
            //return false;

        }else if(action.equals("waitForSlotEvent")){


            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {

                    while (!Thread.currentThread().isInterrupted()) {
                        Log.d("waitForSlotEvent", "init");

                        NativeLongByReference slotId = new NativeLongByReference();
                        NativeLong rv;

                        rv = RtPkcs11Library.getInstance().C_WaitForSlotEvent(new NativeLong(0), slotId, null);

                        Log.d("waitForSlotEvent", "bef C_WaitForSlotEvent");

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


                            jsonObjResult.put("slotId", slotId.getValue().toString());

                            if ((Pkcs11Constants.CKF_TOKEN_PRESENT & slotInfo.flags.longValue()) != 0x00) {
                                jsonObjResult.put("event", "add");
                                Log.d("waitForSlotEvent", "add");

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
                                //new SlotEventThread.SlotEvent(slotId, slotInfo)
                                Log.d("waitForSlotEvent", "add");
                            } else {
                                Log.d("waitForSlotEvent", "remove");
                                jsonObjResult.put("event", "remove");
                            }

                            Log.d("waitForSlotEvent", "tokenInfo");

                            jsonObjResult.put("tokenInfo", jsonObjTokenInfo);

                            jsonResult = jsonObjResult.toString();

                            //callbackContext.success(jsonResult);


                            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, jsonResult);
                            pluginResult.setKeepCallback(true);
                            callbackContext.sendPluginResult(pluginResult);


                            //addSlot();
                        } catch (Exception e) {
                            //TokenManager.getInstance().postEvent(new TokenManagerEvent(SLOT_EVENT_THREAD_FAILED));
                            callbackContext.error("slot error");
                        }
                    }
                }
            });


            return true;

        }else if(action.equals("getCertificates")){

            Log.v(getClass().getName(), "init getCertificates");

            try {

                NativeLong slotId = new NativeLong(args.getInt(0));

                NativeLong session = openSession(slotId);

               final HashMap<String, CertificateAndKeyPair> mCertificateMap = new HashMap<>();

                Certificate.CertificateCategory[] supportedCategories = {Certificate.CertificateCategory.UNSPECIFIED, Certificate.CertificateCategory.USER};

                JSONArray jsonArrResult = new JSONArray();

                for (Certificate.CertificateCategory category : supportedCategories) {
                    JSONObject jsonObject = new JSONObject();

                    Map<String, CertificateAndKeyPair> certMap =  getCertificatesWithCategory(category, session);

                    //jsonObject.put("", certMap.);
                    //jsonArrResult.put(jsonObject);


                    mCertificateMap.putAll(certMap);

                    jsonArrResult.put(jsonObject);
                }

                Log.v("cert+++++++", mCertificateMap.toString());

                closeSession(session);

            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }else if(action.equals("getTokenInfo")){
            try {
                Log.v(getClass().getName(), "init getTokenInfo");
                Log.v(getClass().getName(), args.getString(0));
                Log.v(getClass().getName(), args.toString());
                try {

                    NativeLong rv;

                   /* CK_C_INITIALIZE_ARGS initializeArgs = new CK_C_INITIALIZE_ARGS(null, null,
                            null, null, new NativeLong(Pkcs11Constants.CKF_OS_LOCKING_OK), null);
                    rv = RtPkcs11Library.getInstance().C_Initialize(initializeArgs);
                    Pkcs11Exception.throwIfNotOk(rv);*/

                    NativeLong slotId = new NativeLong(0);

                    final CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
                    Pkcs11Exception.throwIfNotOk(
                            RtPkcs11Library.getInstance().C_GetTokenInfo(slotId, tokenInfo));

                    Log.v(getClass().getName(), "serial find");

                    Log.v(getClass().getName(), String.valueOf(tokenInfo.label));
                    Log.v(getClass().getName(), tokenInfo.serialNumber.toString());



                    /*try{
                        final Token token = new Token(slotId, tokenInfo,false, RtPkcs11Library.getInstance());
                    }catch (Exception e){

                    }



                    try (Token.Session session = new Token.Session(slotId)) {
                        Certificate.CertificateCategory[] supportedCategories = {Certificate.CertificateCategory.UNSPECIFIED, Certificate.CertificateCategory.USER};
                        for (Certificate.CertificateCategory category : supportedCategories) {
                            mCertificateMap.putAll(getCertificatesWithCategory(category, session.get()));
                        }
                    }*/



                    callbackContext.success("success");
                    return true;

                } catch (Pkcs11CallerException e) {
                    callbackContext.error(e.getMessage());
                    return false;
                }
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

    private Map<String, CertificateAndKeyPair> getCertificatesWithCategory(Certificate.CertificateCategory category,
                                                                               NativeLong session)
            throws Pkcs11CallerException {

        RtPkcs11 mRtPkcs11 = RtPkcs11Library.getInstance();

        CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        NativeLongByReference certClass =
                new NativeLongByReference(new NativeLong(Pkcs11Constants.CKO_CERTIFICATE));
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

        HashMap<String, CertificateAndKeyPair> certificateMap = new HashMap<>();
        for (NativeLong c : certs) {
            try {
                Log.v("TAG", "___________________________________________________________________");

                Certificate cert = new Certificate(mRtPkcs11, session.longValue(), c.longValue());

                Log.v("TAG", "index=");
                Log.v("TAG", "cert finded");
                Log.v("TAG", cert.getCertificateHolder().getSerialNumber().toString());
                Log.v("TAG", cert.getSubject().toString());

                KeyPair keyPair = KeyPair.getKeyPairByCkaId(mRtPkcs11, session.longValue(), cert.getCkaId());
               // KeyPair keyPair = KeyPair.getKeyPairByCertificate(mRtPkcs11, session.longValue(), cert.getCertificateHolder());

                Log.v("TAG", "af certificateMap");

                certificateMap.put(cert.fingerprint(), new CertificateAndKeyPair(cert, keyPair));

            } catch (Pkcs11CallerException ignore) {
                Log.v("TAG", "ERROR");
                Log.v("TAG", ignore.getMessage());
            }
        }
        return certificateMap;
    }


    @Override public void onDestroy () {
        Log.v("CryptoproPlugin","af ==> ______________ onStop");
        super.onDestroy();
        RtPkcs11Library.getInstance().C_Finalize(null);
        Log.v("CryptoproPlugin","==> ______________ onStop");
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

