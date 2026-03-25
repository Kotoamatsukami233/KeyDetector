package io.github.xiaotong6666.keydetector.checker;

import android.content.Context;
import android.util.Log;
import com.tencent.soter.core.SoterCore;
import com.tencent.soter.core.model.ConstantsSoter;
import com.tencent.soter.core.model.SoterCoreResult;
import com.tencent.soter.soterserver.SoterSessionResult;

public final class SoterSdkSequenceChecker {
    private static final String TAG = "KeyDetectorSoter";
    private static final String TEST_ALIAS_PREFIX = "keydetector_soter_probe_";

    private SoterSdkSequenceChecker() {}

    public static Result probe(Context context, LogSink logSink) {
        StringBuilder ui = new StringBuilder("SOTER 检测：");
        String testAlias = TEST_ALIAS_PREFIX + System.currentTimeMillis();

        boolean nativeSupport = false;
        int coreType = 0;
        boolean trebleConnected = false;
        boolean askOk = false;
        boolean askModelPresent = false;
        boolean askGeneratedByProbe = false;
        boolean askPreExisted = false;
        boolean authOk = false;
        boolean authPresent = false;
        boolean authModelPresent = false;
        boolean keyPrepareOk = false;
        boolean signSessionOk = false;
        long sessionId = -1;

        appendLog(logSink, "Step 1/5: initialize and service reachability");
        try {
            SoterCore.tryToInitSoterBeforeTreble();
            SoterCore.tryToInitSoterTreble(context);
            SoterCore.setUp();

            nativeSupport = SoterCore.isNativeSupportSoter();
            coreType = SoterCore.getSoterCoreType();
            trebleConnected = SoterCore.isTrebleServiceConnected();
            appendLog(
                    logSink,
                    "Native support="
                            + nativeSupport
                            + ", coreType="
                            + coreType
                            + ", trebleConnected="
                            + trebleConnected);
            ui.append("\n1. 初始化与服务：")
                    .append(nativeSupport ? "通过" : "失败")
                    .append(" (coreType=")
                    .append(coreType)
                    .append(", trebleConnected=")
                    .append(trebleConnected)
                    .append(")");
        } catch (Throwable t) {
            appendLog(logSink, "Step 1 failed with exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            ui.append("\n1. 初始化与服务：失败 (").append(t.getClass().getSimpleName()).append(")");
        }

        appendLog(logSink, "Step 2/5: biometric capability");
        try {
            boolean fpHw = SoterCore.isSupportFingerprint(context);
            boolean fpEnrolled = SoterCore.isSystemHasFingerprint(context);
            boolean fpFrozen = SoterCore.isCurrentFingerprintFrozen(context);
            boolean faceHw = SoterCore.isSupportBiometric(context, ConstantsSoter.FACEID_AUTH);
            boolean faceEnrolled = SoterCore.isSystemHasBiometric(context, ConstantsSoter.FACEID_AUTH);
            boolean faceFrozen = SoterCore.isCurrentBiometricFrozen(context, ConstantsSoter.FACEID_AUTH);
            appendLog(
                    logSink,
                    "Fingerprint(hw="
                            + fpHw
                            + ", enrolled="
                            + fpEnrolled
                            + ", frozen="
                            + fpFrozen
                            + "), Face(hw="
                            + faceHw
                            + ", enrolled="
                            + faceEnrolled
                            + ", frozen="
                            + faceFrozen
                            + ")");
            ui.append("\n2. 生物能力：FP(")
                    .append(fpHw ? "硬件有" : "硬件无")
                    .append(", ")
                    .append(fpEnrolled ? "已录入" : "未录入")
                    .append("), Face(")
                    .append(faceHw ? "硬件有" : "硬件无")
                    .append(", ")
                    .append(faceEnrolled ? "已录入" : "未录入")
                    .append(")");
        } catch (Throwable t) {
            appendLog(logSink, "Step 2 failed with exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            ui.append("\n2. 生物能力：检测失败 (").append(t.getClass().getSimpleName()).append(")");
        }

        appendLog(logSink, "Step 3/5: key preparation (ASK/AuthKey)");
        if (nativeSupport) {
            try {
                askPreExisted = SoterCore.hasAppGlobalSecureKey();
                appendLog(logSink, "ASK pre-exists before probe: " + askPreExisted);
                if (askPreExisted) {
                    askOk = true;
                } else {
                    SoterCoreResult askResult = SoterCore.generateAppGlobalSecureKey();
                    askOk = askResult != null && askResult.isSuccess();
                    askGeneratedByProbe = askOk;
                    appendLog(logSink, "ASK generate result: " + toResultLog(askResult));
                }

                askModelPresent = SoterCore.getAppGlobalSecureKeyModel() != null;
                appendLog(logSink, "ASK model present: " + askModelPresent);

                if (askOk) {
                    SoterCoreResult authResult = SoterCore.generateAuthKey(testAlias);
                    authOk = authResult != null && authResult.isSuccess();
                    appendLog(logSink, "AuthKey generate result: " + toResultLog(authResult) + ", alias=" + testAlias);
                    if (authOk) {
                        authPresent = SoterCore.hasAuthKey(testAlias);
                        authModelPresent = SoterCore.getAuthKeyModel(testAlias) != null;
                        appendLog(
                                logSink,
                                "AuthKey presence check: hasAuthKey="
                                        + authPresent
                                        + ", authModelPresent="
                                        + authModelPresent);
                    }
                }

                keyPrepareOk = askOk && askModelPresent && authOk && authPresent && authModelPresent;
                ui.append("\n3. 密钥准备：")
                        .append(keyPrepareOk ? "通过" : "失败")
                        .append(" (ASK=")
                        .append(askOk)
                        .append(", askModel=")
                        .append(askModelPresent)
                        .append(", AuthKey=")
                        .append(authOk)
                        .append(", hasAuthKey=")
                        .append(authPresent)
                        .append(", authModel=")
                        .append(authModelPresent)
                        .append(")");
            } catch (Throwable t) {
                appendLog(
                        logSink,
                        "Step 3 failed with exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                ui.append("\n3. 密钥准备：失败 (").append(t.getClass().getSimpleName()).append(")");
            }
        } else {
            ui.append("\n3. 密钥准备：跳过 (设备不支持 SOTER)");
        }

        appendLog(logSink, "Step 4/5: signing session init");
        if (askOk && authOk && authPresent && authModelPresent) {
            try {
                String challenge = "keydetector_probe_" + System.currentTimeMillis();
                SoterSessionResult sessionResult = SoterCore.initSigh(testAlias, challenge);
                signSessionOk = sessionResult != null && sessionResult.resultCode == 0 && sessionResult.session != 0;
                sessionId = sessionResult != null ? sessionResult.session : -1;
                appendLog(
                        logSink,
                        "initSigh result: session="
                                + sessionId
                                + ", resultCode="
                                + (sessionResult != null ? sessionResult.resultCode : "null"));
                ui.append("\n4. 签名会话：")
                        .append(signSessionOk ? "通过" : "失败")
                        .append(" (session=")
                        .append(sessionId)
                        .append(")");
            } catch (Throwable t) {
                appendLog(
                        logSink,
                        "Step 4 failed with exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                ui.append("\n4. 签名会话：失败 (").append(t.getClass().getSimpleName()).append(")");
            }
        } else {
            ui.append("\n4. 签名会话：跳过 (密钥准备未通过)");
        }

        appendLog(logSink, "Step 5/5: cleanup probe keys");
        boolean removeAuthOk = false;
        boolean removeAskOk = false;
        boolean removeAskSkipped = false;
        try {
            SoterCoreResult removeAuthResult = SoterCore.removeAuthKey(testAlias, false);
            removeAuthOk = removeAuthResult != null && removeAuthResult.isSuccess();
            appendLog(logSink, "removeAuthKey result: " + toResultLog(removeAuthResult));
        } catch (Throwable t) {
            appendLog(logSink, "removeAuthKey exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        if (askGeneratedByProbe) {
            try {
                SoterCoreResult removeAskResult = SoterCore.removeAppGlobalSecureKey();
                removeAskOk = removeAskResult != null && removeAskResult.isSuccess();
                appendLog(logSink, "removeAppGlobalSecureKey result: " + toResultLog(removeAskResult));
            } catch (Throwable t) {
                appendLog(
                        logSink,
                        "removeAppGlobalSecureKey exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        } else {
            removeAskSkipped = true;
            appendLog(logSink, "Skip removeAppGlobalSecureKey: ASK pre-existed or not created by probe");
        }
        ui.append("\n5. 清理：")
                .append(removeAuthOk || removeAskOk || removeAskSkipped ? "已执行" : "可能未执行")
                .append(" (removeAuthKey=")
                .append(removeAuthOk)
                .append(", removeASK=")
                .append(removeAskOk)
                .append(", removeASKSkipped=")
                .append(removeAskSkipped)
                .append(")");

        boolean initServiceOk = nativeSupport && trebleConnected;
        boolean overallOk = initServiceOk && keyPrepareOk && signSessionOk;
        return new Result(initServiceOk, keyPrepareOk, signSessionOk, overallOk, ui.toString());
    }

    private static String toResultLog(SoterCoreResult result) {
        if (result == null) {
            return "null";
        }
        return "errCode=" + result.errCode + ", errMsg=" + result.errMsg;
    }

    private static void appendLog(LogSink logSink, String message) {
        Log.i(TAG, message);
        if (logSink != null) {
            logSink.append("[SOTER] " + message);
        }
    }

    public interface LogSink {
        void append(String message);
    }

    public static final class Result {
        public final boolean initServiceOk;
        public final boolean keyPrepareOk;
        public final boolean signSessionOk;
        public final boolean overallOk;
        public final String uiSummary;

        public Result(
                boolean initServiceOk,
                boolean keyPrepareOk,
                boolean signSessionOk,
                boolean overallOk,
                String uiSummary) {
            this.initServiceOk = initServiceOk;
            this.keyPrepareOk = keyPrepareOk;
            this.signSessionOk = signSessionOk;
            this.overallOk = overallOk;
            this.uiSummary = uiSummary;
        }
    }
}
