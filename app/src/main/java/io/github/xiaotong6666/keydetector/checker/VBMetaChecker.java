package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Util.getSystemProperty;
import static io.github.xiaotong6666.keydetector.Util.hexStringToByteArray;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.RootOfTrust;
import java.util.Arrays;

/**
 * VBMeta / RootOfTrust 综合检测器
 *
 * 检测原理：
 * - 统一使用 attestation leaf 证书中的 RootOfTrust 作为数据源
 * - RootOfTrust 里同时包含 deviceLocked、verifiedBootState、verifiedBootHash
 * - 这三个字段原本分散在多个 checker 中，语义上都属于 Verified Boot / Boot 状态一致性检查
 *
 * 检测方法：
 * 1. 从当前 attestation 证书解析 RootOfTrust
 * 2. 检查 deviceLocked 是否为 false
 * 3. 检查 verifiedBootState 是否不是 VERIFIED(0)
 * 4. 若 verifiedBootHash 不是全零占位值，则继续与 ro.boot.vbmeta.digest 比对
 *
 * 判定规则：
 * - deviceLocked == false 视为异常
 * - verifiedBootState != VERIFIED 视为异常
 * - verifiedBootHash 与系统 vbmeta digest 不一致视为异常
 *
 * 检测目标：
 * - Bootloader 已解锁
 * - Verified Boot 状态异常（SELF_SIGNED / UNVERIFIED / FAILED）
 * - attestation 声明的 vbmeta 与系统当前 vbmeta 不一致
 */
public final class VBMetaChecker extends Checker {
    private static final String TAG = "VBMetaChecker";
    private static final int KM_VERIFIED_BOOT_VERIFIED = 0;
    private static final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
    private static final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
    private static final int KM_VERIFIED_BOOT_FAILED = 3;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        RootOfTrust rot = RootOfTrust.parse(ctx.certChain.get(0));
        if (rot == null) return false;
        Log.d(TAG, "rot: " + rot);

        boolean anomaly = false;

        Boolean deviceLocked = rot.getDeviceLocked();
        if (Boolean.FALSE.equals(deviceLocked)) {
            Log.e(TAG, "ANOMALY: Bootloader is UNLOCKED - deviceLocked=false in attestation");
            anomaly = true;
        }

        Integer verifiedBootState = rot.getVerifiedBootState();
        if (verifiedBootState != null && verifiedBootState != KM_VERIFIED_BOOT_VERIFIED) {
            Log.e(TAG, "ANOMALY: Verified Boot State = " + verifiedBootStateToString(verifiedBootState));
            anomaly = true;
        }

        boolean isDummyHash = true;
        byte[] hash = rot.getVerifiedBootHash();
        if (hash != null) {
            for (byte b : hash) {
                if (b != 0) {
                    isDummyHash = false;
                    break;
                }
            }
        }

        String systemDigestHex = getSystemProperty("ro.boot.vbmeta.digest");
        if (systemDigestHex != null && !systemDigestHex.isEmpty()) {
            byte[] systemVBMetaDigest = hexStringToByteArray(systemDigestHex);
            boolean digestMismatchHash = !isDummyHash && !Arrays.equals(systemVBMetaDigest, hash);
            if (digestMismatchHash) {
                Log.e(TAG, "ANOMALY: vbmeta digest mismatch between system property and attestation RootOfTrust");
                anomaly = true;
            }
        }

        return anomaly;
    }

    private static String verifiedBootStateToString(int state) {
        switch (state) {
            case KM_VERIFIED_BOOT_VERIFIED:
                return "VERIFIED";
            case KM_VERIFIED_BOOT_SELF_SIGNED:
                return "SELF_SIGNED";
            case KM_VERIFIED_BOOT_UNVERIFIED:
                return "UNVERIFIED";
            case KM_VERIFIED_BOOT_FAILED:
                return "FAILED";
            default:
                return "UNKNOWN(" + state + ")";
        }
    }

    @Override
    public String description() {
        return "VBMeta / RootOfTrust Anomaly (%d)\nVBMeta Hash 不一致、Bootloader 已解锁或 Verified Boot 状态异常";
    }
}
