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
    private static final int MAX_WECHAT_PREPARE_RETRY = 3;

    private SoterSdkSequenceChecker() {}

    public static Result probe(Context context, LogSink logSink) {
        StringBuilder ui = new StringBuilder("SOTER 检测：");
        String testAlias = TEST_ALIAS_PREFIX + System.currentTimeMillis();

        boolean nativeSupport = false;
        int coreType = 0;
        boolean trebleConnected = false;
        boolean servicePresenceKnown = false;
        boolean servicePresent = false;
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
        int prepareRetryCount = 0;
        int finalPrepareErrCode = 0;
        String finalPrepareErrMsg = "ok";

        appendLog(logSink, "Step 1/5: initialize and service reachability");
        try {
            SoterCore.tryToInitSoterBeforeTreble();
            SoterCore.tryToInitSoterTreble(context);
            SoterCore.setUp();

            nativeSupport = SoterCore.isNativeSupportSoter();
            coreType = SoterCore.getSoterCoreType();
            trebleConnected = SoterCore.isTrebleServiceConnected();
            servicePresenceKnown = true;
            servicePresent = nativeSupport;
            appendLog(
                    logSink,
                    "Native support="
                            + nativeSupport
                            + ", coreType="
                            + coreType
                            + ", trebleConnected="
                            + trebleConnected);
            String initStatus = !nativeSupport ? "跳过" : (trebleConnected ? "通过" : "已发现");
            ui.append("\n1. 初始化与服务：")
                    .append(initStatus)
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
                PrepareState prepareState = prepareKeyLikeWechat(testAlias, logSink);
                askPreExisted = prepareState.askPreExisted;
                askGeneratedByProbe = prepareState.askGeneratedByProbe;
                askOk = prepareState.askOk;
                askModelPresent = prepareState.askModelPresent;
                authOk = prepareState.authOk;
                authPresent = prepareState.authPresent;
                authModelPresent = prepareState.authModelPresent;
                keyPrepareOk = prepareState.keyPrepareOk;
                prepareRetryCount = prepareState.retryCount;
                finalPrepareErrCode = prepareState.finalErrCode;
                finalPrepareErrMsg = prepareState.finalErrMsg;

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
                        .append(", retries=")
                        .append(prepareRetryCount)
                        .append(", finalErr=")
                        .append(finalPrepareErrCode)
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
        // WeChat-like cleanup expectation:
        // if ASK did not pre-exist before probe, try to remove it in cleanup.
        // Using askPreExisted is more stable than askGeneratedByProbe in remote-proxy mode,
        // where ASK may become available through fallback paths.
        if (nativeSupport) {
            try {
                SoterCoreResult removeAskResult = SoterCore.removeAppGlobalSecureKey();
                removeAskOk = removeAskResult != null
                        && (removeAskResult.isSuccess() || isCleanupNonFatal(removeAskResult.errCode));
                appendLog(logSink, "removeAppGlobalSecureKey result: " + toResultLog(removeAskResult));
            } catch (Throwable t) {
                appendLog(
                        logSink,
                        "removeAppGlobalSecureKey exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        } else {
            removeAskSkipped = true;
            appendLog(logSink, "Skip removeAppGlobalSecureKey: nativeSupport=false");
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
        // Missing SOTER service is treated as not-applicable for UI coloring.
        // Only mark the SOTER block as failed when the service is present but follow-up key/sign steps fail.
        boolean overallOk;
        if (servicePresenceKnown && !servicePresent) {
            overallOk = true;
        } else if (servicePresenceKnown) {
            overallOk = keyPrepareOk && signSessionOk;
        } else {
            overallOk = false;
        }
        return new Result(initServiceOk, keyPrepareOk, signSessionOk, overallOk, ui.toString());
    }

    private static PrepareState prepareKeyLikeWechat(String testAlias, LogSink logSink) {
        PrepareState state = new PrepareState();
        state.askPreExisted = SoterCore.hasAppGlobalSecureKey();
        appendLog(logSink, "ASK pre-exists before probe: " + state.askPreExisted);

        int lastErrCode = 0;
        String lastErrMsg = "ok";
        for (int attempt = 0; attempt < MAX_WECHAT_PREPARE_RETRY; attempt++) {
            state.retryCount = attempt;
            appendLog(logSink, "prepareAuthKey attempt=" + attempt);

            // WeChat: second retry path removes ASK first.
            if (attempt == 1) {
                SoterCoreResult rmAsk = SoterCore.removeAppGlobalSecureKey();
                appendLog(logSink, "wechat-like retry path: remove ASK before retry, result=" + toResultLog(rmAsk));
            }

            boolean askExists = SoterCore.hasAppGlobalSecureKey();
            if (!askExists) {
                SoterCoreResult askResult = SoterCore.generateAppGlobalSecureKey();
                appendLog(logSink, "ASK generate result: " + toResultLog(askResult));
                askExists = askResult != null && askResult.isSuccess();
                if (askExists) {
                    state.askGeneratedByProbe = true;
                } else {
                    lastErrCode = askResult != null ? askResult.errCode : -999;
                    lastErrMsg = askResult != null ? askResult.errMsg : "ASK generate result null";
                    appendLog(logSink, "prepare fail category: " + mapWechatPrepareError(lastErrCode, lastErrMsg));
                    continue;
                }
            }

            state.askOk = askExists;
            state.askModelPresent = SoterCore.getAppGlobalSecureKeyModel() != null;
            appendLog(logSink, "ASK model present: " + state.askModelPresent);

            if (!state.askModelPresent) {
                lastErrCode = 1003;
                lastErrMsg = "ask model missing";
                appendLog(logSink, "prepare fail category: " + mapWechatPrepareError(lastErrCode, lastErrMsg));
                continue;
            }

            SoterCoreResult authResult = SoterCore.generateAuthKey(testAlias);
            state.authOk = authResult != null && authResult.isSuccess();
            appendLog(logSink, "AuthKey generate result: " + toResultLog(authResult) + ", alias=" + testAlias);
            if (!state.authOk) {
                lastErrCode = authResult != null ? authResult.errCode : -999;
                lastErrMsg = authResult != null ? authResult.errMsg : "AuthKey generate result null";
                appendLog(logSink, "prepare fail category: " + mapWechatPrepareError(lastErrCode, lastErrMsg));
                continue;
            }

            state.authPresent = SoterCore.hasAuthKey(testAlias);
            state.authModelPresent = SoterCore.getAuthKeyModel(testAlias) != null;
            appendLog(
                    logSink,
                    "AuthKey presence check: hasAuthKey="
                            + state.authPresent
                            + ", authModelPresent="
                            + state.authModelPresent);

            if (!state.authPresent || !state.authModelPresent) {
                lastErrCode = 1006;
                lastErrMsg = "auth key model is null or auth key absent after generation";
                appendLog(logSink, "prepare fail category: " + mapWechatPrepareError(lastErrCode, lastErrMsg));
                continue;
            }

            state.keyPrepareOk = true;
            state.finalErrCode = 0;
            state.finalErrMsg = "ok";
            return state;
        }

        state.finalErrCode = lastErrCode;
        state.finalErrMsg = lastErrMsg;
        return state;
    }

    private static String mapWechatPrepareError(int errCode, String errMsg) {
        String detail = " (errCode=" + errCode + ", errMsg=" + errMsg + ")";
        if (errCode == 1006) {
            return "hy: failed upload: model is null or necessary elements null" + detail;
        }
        if (errCode == 1004) {
            return "hy: update pay auth key failed. remove" + detail;
        }
        if (errCode == 1003) {
            return "upload ask failed" + detail;
        }
        if (errCode == 6) {
            return "hy: gen auth key failed" + detail;
        }
        if (errCode == 4 || errCode == 3) {
            return "hy: gen auth key failed" + detail;
        }
        return "unknown error when prepare auth key" + detail;
    }

    private static final class PrepareState {
        boolean askPreExisted;
        boolean askGeneratedByProbe;
        boolean askOk;
        boolean askModelPresent;
        boolean authOk;
        boolean authPresent;
        boolean authModelPresent;
        boolean keyPrepareOk;
        int retryCount;
        int finalErrCode;
        String finalErrMsg;
    }

    private static String toResultLog(SoterCoreResult result) {
        if (result == null) {
            return "null";
        }
        return "errCode=" + result.errCode + ", errMsg=" + result.errMsg;
    }

    private static boolean isCleanupNonFatal(int errCode) {
        // Different ROM/SOTER impls may return non-zero for "not found/already clean".
        return errCode == 7 || errCode == -5 || errCode == -300;
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
