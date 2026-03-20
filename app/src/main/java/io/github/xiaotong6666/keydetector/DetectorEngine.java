package io.github.xiaotong6666.keydetector;

import static io.github.xiaotong6666.keydetector.Constant.RESULT_TRUSTED;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_AOSP;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_GOOGLE_F;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_GOOGLE_I;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_UNKNOWN;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_VENDOR_REQUIRED;

import android.util.Log;
import io.github.xiaotong6666.keydetector.checker.AOSPRootChecker;
import io.github.xiaotong6666.keydetector.checker.AttestKeyHookChecker;
import io.github.xiaotong6666.keydetector.checker.AttestationComplianceChecker;
import io.github.xiaotong6666.keydetector.checker.AttestationSecurityLevelChecker;
import io.github.xiaotong6666.keydetector.checker.BehaviorChecker;
import io.github.xiaotong6666.keydetector.checker.BinderConsistencyChecker;
import io.github.xiaotong6666.keydetector.checker.BinderHookChecker;
import io.github.xiaotong6666.keydetector.checker.BiometricTeeIntegrationChecker;
import io.github.xiaotong6666.keydetector.checker.BouncyCastleChainChecker;
import io.github.xiaotong6666.keydetector.checker.ChallengeChecker;
import io.github.xiaotong6666.keydetector.checker.Checker;
import io.github.xiaotong6666.keydetector.checker.KeyConsistencyChecker;
import io.github.xiaotong6666.keydetector.checker.KeyIdMetadataChecker;
import io.github.xiaotong6666.keydetector.checker.KeyMetadataShapeChecker;
import io.github.xiaotong6666.keydetector.checker.KeystoreInteractionChecker;
import io.github.xiaotong6666.keydetector.checker.ListEntriesBatchedChecker;
import io.github.xiaotong6666.keydetector.checker.ListEntriesChecker;
import io.github.xiaotong6666.keydetector.checker.OperationErrorPathChecker;
import io.github.xiaotong6666.keydetector.checker.PatchModeChecker;
import io.github.xiaotong6666.keydetector.checker.RevokedKeyChecker;
import io.github.xiaotong6666.keydetector.checker.SecurityLevelChecker;
import io.github.xiaotong6666.keydetector.checker.StrongBoxFunctionalityChecker;
import io.github.xiaotong6666.keydetector.checker.UnknownRootChecker;
import io.github.xiaotong6666.keydetector.checker.UpdateSubcompChecker;
import io.github.xiaotong6666.keydetector.checker.VBMetaChecker;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DetectorEngine {
    private static final int ERR_BINDER_CONSISTENCY = 1 << 1;
    private static final int ERR_BINDER_HOOK = 1 << 2;
    private static final int ERR_AOSP_ROOT = 1 << 3;
    private static final int ERR_UNKNOWN_ROOT = 1 << 4;
    private static final int ERR_CHALLENGE = 1 << 5;
    private static final int ERR_BROKEN_CHAIN = 1 << 6;
    private static final int ERR_KEY_MISMATCH = 1 << 7;
    private static final int ERR_REVOKED_KEY = 1 << 8;
    private static final int ERR_PATCH_MODE = 1 << 9;
    private static final int ERR_ATTEST_COMPLIANCE = 1 << 10;
    private static final int ERR_VBMETA_STATE = 1 << 11;
    private static final int ERR_KEYSTORE_LRU = 1 << 12;
    private static final int ERR_LIST_ENTRIES = 1 << 13;
    private static final int ERR_STATE_INCONSISTENCY = 1 << 14;
    private static final int ERR_SECURITY_LEVEL = 1 << 15;
    private static final int ERR_INJECTION = 1 << 16;
    private static final int ERR_ATTESTATION_SECURITY_LEVEL = 1 << 17;
    private static final int ERR_HARDWARE_KEYSTORE_INTERACTION = 1 << 18;
    private static final int ERR_STRONGBOX_FUNCTIONALITY = 1 << 19;
    private static final int ERR_KEY_ID_METADATA = 1 << 20;
    private static final int ERR_KEY_METADATA_SHAPE = 1 << 21;
    private static final int ERR_OPERATION_ERROR_PATH = 1 << 22;
    private static final int ERR_LIST_ENTRIES_BATCHED = 1 << 23;
    private static final int ERR_BIOMETRIC_TEE_INTEGRATION = 1 << 24;
    public static final LinkedHashMap<Integer, Checker> FlagCheckerMap = new LinkedHashMap<>();

    static {
        FlagCheckerMap.put(ERR_BINDER_CONSISTENCY, new BinderConsistencyChecker());
        FlagCheckerMap.put(ERR_BINDER_HOOK, new BinderHookChecker());
        FlagCheckerMap.put(ERR_AOSP_ROOT, new AOSPRootChecker());
        FlagCheckerMap.put(ERR_UNKNOWN_ROOT, new UnknownRootChecker());
        FlagCheckerMap.put(ERR_CHALLENGE, new ChallengeChecker());
        FlagCheckerMap.put(ERR_BROKEN_CHAIN, new BouncyCastleChainChecker());
        FlagCheckerMap.put(ERR_KEY_MISMATCH, new KeyConsistencyChecker());
        FlagCheckerMap.put(ERR_REVOKED_KEY, new RevokedKeyChecker());
        FlagCheckerMap.put(ERR_PATCH_MODE, new PatchModeChecker());
        FlagCheckerMap.put(ERR_ATTEST_COMPLIANCE, new AttestationComplianceChecker());
        FlagCheckerMap.put(ERR_VBMETA_STATE, new VBMetaChecker());
        FlagCheckerMap.put(ERR_KEYSTORE_LRU, new BehaviorChecker());
        FlagCheckerMap.put(ERR_LIST_ENTRIES, new ListEntriesChecker());
        FlagCheckerMap.put(ERR_STATE_INCONSISTENCY, new UpdateSubcompChecker());
        FlagCheckerMap.put(ERR_SECURITY_LEVEL, new SecurityLevelChecker());
        FlagCheckerMap.put(ERR_INJECTION, new AttestKeyHookChecker());
        FlagCheckerMap.put(ERR_ATTESTATION_SECURITY_LEVEL, new AttestationSecurityLevelChecker());
        FlagCheckerMap.put(ERR_HARDWARE_KEYSTORE_INTERACTION, new KeystoreInteractionChecker());
        FlagCheckerMap.put(ERR_STRONGBOX_FUNCTIONALITY, new StrongBoxFunctionalityChecker());
        FlagCheckerMap.put(ERR_KEY_ID_METADATA, new KeyIdMetadataChecker());
        FlagCheckerMap.put(ERR_KEY_METADATA_SHAPE, new KeyMetadataShapeChecker());
        FlagCheckerMap.put(ERR_OPERATION_ERROR_PATH, new OperationErrorPathChecker());
        FlagCheckerMap.put(ERR_LIST_ENTRIES_BATCHED, new ListEntriesBatchedChecker());
        FlagCheckerMap.put(ERR_BIOMETRIC_TEE_INTEGRATION, new BiometricTeeIntegrationChecker());
    }

    public int run(CheckerContext ctx) {
        int result = 0;

        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            try {
                if (entry.getValue() == null) continue; // ?
                boolean hit = entry.getValue().check(ctx);
                if (hit) {
                    result |= entry.getKey();
                    Log.e(
                            "Detector",
                            "Hit: " + entry.getValue().name() + " flag=0x" + Integer.toHexString(entry.getKey()));
                }
            } catch (Throwable t) {
                Log.e("Detector", "Checker crashed: " + entry.getValue().name(), t);
                result |= 2;
            }
        }

        if ((result & ERR_PATCH_MODE) != 0) {
            result |= 2;
        }

        boolean locked = false;
        boolean verified = false;
        RootOfTrust rot = null;
        if (ctx.certChain != null && !ctx.certChain.isEmpty()) {
            rot = RootOfTrust.parse(ctx.certChain.get(0));
            locked = rot != null && Boolean.TRUE.equals(rot.getDeviceLocked());
            verified = rot != null && Integer.valueOf(0).equals(rot.getVerifiedBootState());
        }

        if (result == 0) {
            if (locked && verified) {
                result |= RESULT_TRUSTED;
            }
        }

        boolean trustedBoot = (result & RESULT_TRUSTED) != 0;
        boolean rootTrusted =
                ctx.rootType == ROOT_GOOGLE_F || ctx.rootType == ROOT_GOOGLE_I || ctx.rootType == ROOT_VENDOR_REQUIRED;
        boolean attestationOk = (result
                        & (ERR_BINDER_CONSISTENCY
                                | ERR_CHALLENGE
                                | ERR_BROKEN_CHAIN
                                | ERR_KEY_MISMATCH
                                | ERR_REVOKED_KEY
                                | ERR_PATCH_MODE
                                | ERR_KEYSTORE_LRU
                                | ERR_LIST_ENTRIES
                                | ERR_STATE_INCONSISTENCY
                                | ERR_SECURITY_LEVEL
                                | ERR_INJECTION
                                | ERR_KEY_ID_METADATA
                                | ERR_KEY_METADATA_SHAPE
                                | ERR_OPERATION_ERROR_PATH
                                | ERR_LIST_ENTRIES_BATCHED))
                == 0;

        boolean abnormal = (result & RESULT_TRUSTED) == 0 || (result & ~RESULT_TRUSTED) != 0;
        if (abnormal) {
            Log.e("Detector", "=== Abnormal detection === code=" + result + " (0x" + Integer.toHexString(result) + ")");
            Log.e(
                    "Detector",
                    "TrustedBoot="
                            + trustedBoot
                            + " rootTrusted="
                            + rootTrusted
                            + " rootType="
                            + rootTypeToString(ctx.rootType)
                            + " deviceLocked="
                            + (rot != null ? rot.getDeviceLocked() : "null")
                            + " verifiedBootState="
                            + (rot != null ? rot.getVerifiedBootState() : "null")
                            + " ("
                            + verifiedBootStateToString(rot != null ? rot.getVerifiedBootState() : null)
                            + ")"
                            + " attestationOk="
                            + attestationOk);
            if (rot != null && rot.getVerifiedBootHash() != null) {
                Log.e("Detector", "VerifiedBootHash=" + Util.byteArrayToHexString(rot.getVerifiedBootHash()));
            }
            logResultBits(result);
            Util.logChain("CertificateChain", ctx.certChain);
        }

        Log.i("Detector", "=== Detection Finished. Code: " + result + " ===");

        return result;
    }

    private static String rootTypeToString(int rootType) {
        switch (rootType) {
            case ROOT_AOSP:
                return "AOSP";
            case ROOT_GOOGLE_F:
                return "GOOGLE_F";
            case ROOT_GOOGLE_I:
                return "GOOGLE_I";
            case ROOT_VENDOR_REQUIRED:
                return "VENDOR_REQUIRED";
            case ROOT_UNKNOWN:
            default:
                return "UNKNOWN";
        }
    }

    private static String verifiedBootStateToString(Integer state) {
        if (state == null) return "Unknown(null)";
        int v = state;
        if (v == 0) return "Verified";
        if (v == 1) return "Self-signed";
        if (v == 2) return "Unverified";
        if (v == 3) return "Failed";
        return "Unknown(" + v + ")";
    }

    private static void logResultBits(int code) {
        if ((code & RESULT_TRUSTED) == 0) {
            Log.e("Detector", "Flag missing: Trusted Boot (1)");
        }
        if ((code & ERR_BINDER_CONSISTENCY) != 0) {
            Log.e("Detector", "Flag set: Tampered Attestation Key (" + ERR_BINDER_CONSISTENCY + ")");
        }
        if ((code & ERR_BINDER_HOOK) != 0) {
            Log.e("Detector", "Flag set: Hook Failed (" + ERR_BINDER_HOOK + ")");
        }
        if ((code & ERR_AOSP_ROOT) != 0) {
            Log.e("Detector", "Flag set: AOSP Attestation Key (" + ERR_AOSP_ROOT + ")");
        }
        if ((code & ERR_UNKNOWN_ROOT) != 0) {
            Log.e("Detector", "Flag set: Unknown Attestation Key (" + ERR_UNKNOWN_ROOT + ")");
        }
        if ((code & ERR_CHALLENGE) != 0) {
            Log.e("Detector", "Flag set: VBMeta/Challenge Mismatch (" + ERR_CHALLENGE + ")");
        }
        if ((code & ERR_BROKEN_CHAIN) != 0) {
            Log.e("Detector", "Flag set: Broken Chain (" + ERR_BROKEN_CHAIN + ")");
        }
        if ((code & ERR_KEY_MISMATCH) != 0) {
            Log.e("Detector", "Flag set: Key Mismatch (" + ERR_KEY_MISMATCH + ")");
        }
        if ((code & ERR_REVOKED_KEY) != 0) {
            Log.e("Detector", "Flag set: Revoked Key (" + ERR_REVOKED_KEY + ")");
        }
        if ((code & ERR_PATCH_MODE) != 0) {
            Log.e("Detector", "Flag set: Patch Mode Detected (" + ERR_PATCH_MODE + ")");
        }
        if ((code & ERR_ATTEST_COMPLIANCE) != 0) {
            Log.e("Detector", "Flag set: Non-compliant Keystore (" + ERR_ATTEST_COMPLIANCE + ")");
        }
        if ((code & ERR_VBMETA_STATE) != 0) {
            Log.e("Detector", "Flag set: VBMeta/State Mismatch (" + ERR_VBMETA_STATE + ")");
        }
        if ((code & ERR_KEYSTORE_LRU) != 0) {
            Log.e("Detector", "Flag set: Keystore 2.0 LRU Pruning Anomaly (" + ERR_KEYSTORE_LRU + ")");
        }
        if ((code & ERR_LIST_ENTRIES) != 0) {
            Log.e("Detector", "Flag set: IKeystoreService ListEntries Anomaly (" + ERR_LIST_ENTRIES + ")");
        }
        if ((code & ERR_STATE_INCONSISTENCY) != 0) {
            Log.e("Detector", "Flag set: IKeystoreService State Inconsistency (" + ERR_STATE_INCONSISTENCY + ")");
        }
        if ((code & ERR_SECURITY_LEVEL) != 0) {
            Log.e("Detector", "Flag set: Keystore 2.0 SecurityLevel Anomaly (" + ERR_SECURITY_LEVEL + ")");
        }
        if ((code & ERR_INJECTION) != 0) {
            Log.e("Detector", "Flag set: Custom Attestation Key Injection Possible (" + ERR_INJECTION + ")");
        }
        if ((code & ERR_ATTESTATION_SECURITY_LEVEL) != 0) {
            Log.e("Detector", "Flag set: Software-level Attestation Detected (" + ERR_ATTESTATION_SECURITY_LEVEL + ")");
        }
        if ((code & ERR_HARDWARE_KEYSTORE_INTERACTION) != 0) {
            Log.e(
                    "Detector",
                    "Flag set: Hardware Keystore Interaction Anomaly (" + ERR_HARDWARE_KEYSTORE_INTERACTION + ")");
        }
        if ((code & ERR_STRONGBOX_FUNCTIONALITY) != 0) {
            Log.e("Detector", "Flag set: StrongBox Functionality Anomaly (" + ERR_STRONGBOX_FUNCTIONALITY + ")");
        }
        if ((code & ERR_KEY_ID_METADATA) != 0) {
            Log.e("Detector", "Flag set: KeyMetadata KEY_ID Semantics Anomaly (" + ERR_KEY_ID_METADATA + ")");
        }
        if ((code & ERR_KEY_METADATA_SHAPE) != 0) {
            Log.e("Detector", "Flag set: KeyMetadata Shape Anomaly (" + ERR_KEY_METADATA_SHAPE + ")");
        }
        if ((code & ERR_OPERATION_ERROR_PATH) != 0) {
            Log.e("Detector", "Flag set: IKeystoreOperation Error-Path Anomaly (" + ERR_OPERATION_ERROR_PATH + ")");
        }
        if ((code & ERR_LIST_ENTRIES_BATCHED) != 0) {
            Log.e(
                    "Detector",
                    "Flag set: IKeystoreService ListEntriesBatched Anomaly (" + ERR_LIST_ENTRIES_BATCHED + ")");
        }
        if ((code & ERR_BIOMETRIC_TEE_INTEGRATION) != 0) {
            Log.e("Detector", "Flag set: Biometric TEE Integration Anomaly (" + ERR_BIOMETRIC_TEE_INTEGRATION + ")");
        }
    }
}
