/*
 * Copyright (c) 2018, JSC Aktiv-Soft. See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package ru.rutoken.pkcs11caller;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.FragmentManager;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

import ru.rutoken.bcprovider.CmsSigner;
import ru.rutoken.pkcs11caller.Certificate.CertificateCategory;
import ru.rutoken.pkcs11caller.exception.CertNotFoundException;
import ru.rutoken.pkcs11caller.exception.GeneralErrorException;
import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO_EXTENDED;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

public class Token {
    private final boolean mIsNfc;
    private final HashMap<String, CertificateAndGostKeyPair> mCertificateMap = new HashMap<>();
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final RtPkcs11 mRtPkcs11;
    private String mPin = "";
    private String mLabel;
    private String mModel;
    private String mSerialNumber;
    private String mShortDecSerialNumber;
    private String mHardwareVersion;
    private int mTotalMemory;
    private int mFreeMemory;
    private int mCharge;
    private int mUserPinRetriesLeft;
    private int mAdminPinRetriesLeft;
    private BodyColor mColor;
    private UserChangePolicy mUserPinChangePolicy;
    private boolean mSupportsSM;
    private SmInitializedStatus mSmInitializedStatus = SmInitializedStatus.UNKNOWN;

    Token(NativeLong slotId, CK_TOKEN_INFO tokenInfo, boolean isNfc, RtPkcs11 pkcs11) throws Pkcs11CallerException {
        mRtPkcs11 = Objects.requireNonNull(pkcs11);
        mIsNfc = isNfc;
        initTokenInfo(slotId, tokenInfo);
        initCertificateList(slotId);
    }

    public boolean isNfc() {
        return mIsNfc;
    }

    public String getLabel() {
        return mLabel;
    }

    public String getModel() {
        return mModel;
    }

    public String getSerialNumber() {
        return mSerialNumber;
    }

    public String getShortDecSerialNumber() {
        return mShortDecSerialNumber;
    }

    public String getHardwareVersion() {
        return mHardwareVersion;
    }

    public int getTotalMemory() {
        return mTotalMemory;
    }

    public int getFreeMemory() {
        return mFreeMemory;
    }

    public int getCharge() {
        return mCharge;
    }

    public int getUserPinRetriesLeft() {
        return mUserPinRetriesLeft;
    }

    public int getAdminPinRetriesLeft() {
        return mAdminPinRetriesLeft;
    }

    public BodyColor getColor() {
        return mColor;
    }

    public UserChangePolicy getUserPinChangePolicy() {
        return mUserPinChangePolicy;
    }

    public boolean supportsSM() {
        return mSupportsSM;
    }

    public SmInitializedStatus smInitializedStatus() {
        return mSmInitializedStatus;
    }

    public void clearPin() {
        // TODO: implement secure pin caching
        mPin = "";
    }

    private Map<String, CertificateAndGostKeyPair> getCertificatesWithCategory(CertificateCategory category,
                                                                               NativeLong session)
            throws Pkcs11CallerException {
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

        HashMap<String, CertificateAndGostKeyPair> certificateMap = new HashMap<>();
        for (NativeLong c : certs) {
            try {
                Certificate cert = new Certificate(mRtPkcs11, session.longValue(), c.longValue());

                Log.v("TAG", "index=");

                GostKeyPair keyPair = GostKeyPair.getGostKeyPairByCertificate(mRtPkcs11,
                        session.longValue(), cert.getCertificateHolder(), cert.getCkaId());
                certificateMap.put(cert.fingerprint(), new CertificateAndGostKeyPair(cert, keyPair));

            } catch (Pkcs11CallerException ignore) {
            }
        }
        return certificateMap;
    }

    private void initTokenInfo(NativeLong slotId, CK_TOKEN_INFO tokenInfo) throws Pkcs11CallerException {
        CK_TOKEN_INFO_EXTENDED tokenInfoEx = new CK_TOKEN_INFO_EXTENDED();
        tokenInfoEx.ulSizeofThisStructure = new NativeLong(tokenInfoEx.size());

        NativeLong rv = mRtPkcs11.C_EX_GetTokenInfoExtended(slotId, tokenInfoEx);
        Pkcs11Exception.throwIfNotOk(rv);

        mLabel = Utils.removeTrailingSpaces(tokenInfo.label);
        mModel = Utils.removeTrailingSpaces(tokenInfo.model);
        mSerialNumber = Utils.removeTrailingSpaces(tokenInfo.serialNumber);
        long decSerial = Long.parseLong(mSerialNumber, 16);
        String decSerialString = String.valueOf(decSerial);
        mShortDecSerialNumber = String.valueOf(decSerial % 100000);
        mHardwareVersion = String.format("%d.%d.%d.%d",
                tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor,
                tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
        mTotalMemory = tokenInfo.ulTotalPublicMemory.intValue();
        mFreeMemory = tokenInfo.ulFreePublicMemory.intValue();
        mCharge = tokenInfoEx.ulBatteryVoltage.intValue();
        mUserPinRetriesLeft = tokenInfoEx.ulUserRetryCountLeft.intValue();
        mAdminPinRetriesLeft = tokenInfoEx.ulAdminRetryCountLeft.intValue();

        if (tokenInfoEx.ulBodyColor.longValue() == RtPkcs11Constants.TOKEN_BODY_COLOR_WHITE) {
            mColor = BodyColor.WHITE;
        } else if (tokenInfoEx.ulBodyColor.longValue() == RtPkcs11Constants.TOKEN_BODY_COLOR_BLACK) {
            mColor = BodyColor.BLACK;
        } else if (tokenInfoEx.ulBodyColor.longValue() == RtPkcs11Constants.TOKEN_BODY_COLOR_UNKNOWN) {
            mColor = BodyColor.UNKNOWN;
        }

        if (((tokenInfoEx.flags.longValue() & RtPkcs11Constants.TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN) != 0x00)
                && ((tokenInfoEx.flags.longValue() & RtPkcs11Constants.TOKEN_FLAGS_USER_CHANGE_USER_PIN) != 0x00)) {
            mUserPinChangePolicy = UserChangePolicy.BOTH;
        } else if (((tokenInfoEx.flags.longValue() & RtPkcs11Constants.TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN) != 0x00)) {
            mUserPinChangePolicy = UserChangePolicy.SO;
        } else {
            mUserPinChangePolicy = UserChangePolicy.USER;
        }

        mSupportsSM = ((tokenInfoEx.flags.longValue() & RtPkcs11Constants.TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING) != 0);
    }

    private void initCertificateList(NativeLong slotId) throws Pkcs11CallerException {
        try (Session session = new Session(slotId)) {
            CertificateCategory[] supportedCategories = {CertificateCategory.UNSPECIFIED, CertificateCategory.USER};
            for (CertificateCategory category : supportedCategories) {
                mCertificateMap.putAll(getCertificatesWithCategory(category, session.get()));
            }
        }
    }

    public Set<String> enumerateCertificates() {
        return mCertificateMap.keySet();
    }

    public Certificate getCertificate(String fingerprint) {
        return Objects.requireNonNull(mCertificateMap.get(fingerprint)).getCertificate();
    }


    public enum UserChangePolicy {
        USER, SO, BOTH
    }

    public enum BodyColor {
        WHITE, BLACK, UNKNOWN
    }

    public enum SmInitializedStatus {
        UNKNOWN, NEED_INITIALIZE, INITIALIZED
    }

    private class Session implements AutoCloseable {
        private NativeLong mSession;

        Session() throws Pkcs11CallerException {
            final NativeLong slotId;
            try {
                slotId = TokenManager.getInstance().getSlotIdByTokenSerial(getSerialNumber()).get();
            } catch (ExecutionException | CancellationException e) {
                throw new GeneralErrorException("Cannot get slot id", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new GeneralErrorException("Thread was interrupted", e);
            }
            openSession(slotId);
        }

        Session(NativeLong slotId) throws Pkcs11Exception {
            openSession(slotId);
        }

        private void openSession(NativeLong slotId) throws Pkcs11Exception {
            final NativeLongByReference session = new NativeLongByReference();
            final NativeLong rv = mRtPkcs11.C_OpenSession(
                    slotId, new NativeLong(Pkcs11Constants.CKF_SERIAL_SESSION), null, null, session);
            if (rv.longValue() != Pkcs11Constants.CKR_OK) {
                if (rv.longValue() == Pkcs11Constants.CKR_FUNCTION_NOT_SUPPORTED && mSupportsSM)
                    mSmInitializedStatus = SmInitializedStatus.NEED_INITIALIZE;

                throw new Pkcs11Exception(rv);
            }
            mSession = session.getValue();
        }

        @Override
        public void close() {
            try {
                NativeLong rv = mRtPkcs11.C_CloseSession(mSession);
                Pkcs11Exception.throwIfNotOk(rv);
            } catch (Pkcs11CallerException e) {
                e.printStackTrace();
            }
        }

        NativeLong get() {
            return mSession;
        }
    }


}
