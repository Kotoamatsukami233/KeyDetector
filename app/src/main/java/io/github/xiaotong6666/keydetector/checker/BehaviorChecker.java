package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Keystore 2.0 LRU Pruning Behavior Checker
 *
 * 检测原理：
 * - Native Keystore2 使用 LRU (Least Recently Used) 策略管理操作
 * - 最多保留约 15 个活跃操作，超过后会驱逐最旧的操作
 * - 假 TEE 实现（如 TEESimulator）缺乏资源管理，不会驱逐操作
 *
 * 检测方法：
 * 1. 尝试创建 20 个签名操作
 * 2. 对所有操作执行 sign() 操作
 * 3. 统计成功和失败的操作数量及索引
 * 4. 判断标准（参考 DuckDetector）：
 *    a) 如果创建了 ≥32 个操作且全部成功 → 异常
 *    b) 检查失败操作的索引是否符合 LRU 模式
 *    c) 检查驱逐模式：最小成功索引 < 最大失败索引 → 异常
 *
 * 检测目标：
 * - TrickyStore
 * - TEESimulator
 * - 其他缺乏资源管理的假 TEE 实现
 */
public final class BehaviorChecker extends Checker {
    private static final String LRU_TEST_ALIAS = "KeyDetector_LRU";
    private static final int OPERATION_COUNT = 20;
    private static final int EXPECTED_MAX_OPERATIONS = 15;
    private static final int STRICT_THRESHOLD = 32;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (android.os.Build.VERSION.SDK_INT < 31) {
            return false;
        }

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            kpg.initialize(new KeyGenParameterSpec.Builder(LRU_TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            KeyPair keyPair = kpg.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            List<OperationInfo> operations = new ArrayList<>();
            int createdCount = 0;

            for (int i = 0; i < OPERATION_COUNT; i++) {
                try {
                    Signature signature = Signature.getInstance("SHA256withECDSA");
                    signature.initSign(privateKey);
                    signature.update(("pruning_test_" + i).getBytes());
                    operations.add(new OperationInfo(signature, i));
                    createdCount++;
                } catch (Exception e) {
                    Log.d("Keystore2Behavior", "Failed to create operation " + i + ": " + e.getMessage());
                    break;
                }
            }

            int successCount = 0;
            int failedCount = 0;
            List<Integer> failedIndices = new ArrayList<>();
            List<Integer> successIndices = new ArrayList<>();

            for (OperationInfo opInfo : operations) {
                try {
                    opInfo.signature.sign();
                    successCount++;
                    successIndices.add(opInfo.index);
                } catch (Exception e) {
                    failedCount++;
                    failedIndices.add(opInfo.index);
                    Log.d("Keystore2Behavior", "Operation " + opInfo.index + " failed (pruned): " + e.getMessage());
                }
            }

            boolean isLRUPattern = true;

            if (failedCount <= 0 || failedIndices.isEmpty()) {
                isLRUPattern = false;
            } else {
                int lruThreshold = (createdCount - EXPECTED_MAX_OPERATIONS) + failedCount;
                for (Integer failedIndex : failedIndices) {
                    if (failedIndex >= lruThreshold) {
                        isLRUPattern = false;
                        Log.d(
                                "Keystore2Behavior",
                                "Failed index " + failedIndex + " >= threshold " + lruThreshold + ", not LRU pattern");
                        break;
                    }
                }
            }

            if (createdCount >= STRICT_THRESHOLD && successCount == createdCount) {
                Log.e(
                        "Keystore2Behavior",
                        "ANOMALY: No LRU eviction after "
                                + createdCount
                                + " ops (Keystore manages at "
                                + EXPECTED_MAX_OPERATIONS
                                + ")");
                return true;
            }

            if (failedCount <= 0 || isLRUPattern || createdCount <= EXPECTED_MAX_OPERATIONS) {
                Log.d(
                        "Keystore2Behavior",
                        "LRU check passed: created="
                                + createdCount
                                + ", succeeded="
                                + successCount
                                + ", failed="
                                + failedCount
                                + ", isLRU="
                                + isLRUPattern);
                return false;
            }

            if (!successIndices.isEmpty() && !failedIndices.isEmpty()) {
                int minSuccessIndex = Collections.min(successIndices);
                int maxFailedIndex = Collections.max(failedIndices);

                if (minSuccessIndex < maxFailedIndex) {
                    Log.e(
                            "Keystore2Behavior",
                            "ANOMALY: Non-LRU eviction pattern detected. "
                                    + "Min success index ("
                                    + minSuccessIndex
                                    + ") < Max failed index ("
                                    + maxFailedIndex
                                    + ")");
                    return true;
                }
            }

            Log.d(
                    "Keystore2Behavior",
                    "LRU check passed: created="
                            + createdCount
                            + ", succeeded="
                            + successCount
                            + ", failed="
                            + failedCount
                            + ", isLRU="
                            + isLRUPattern);
            return false;

        } catch (Throwable t) {
            Log.w("Keystore2Behavior", "Check execution failed", t);
            return false;
        } finally {
            try {
                if (keyStore.containsAlias(LRU_TEST_ALIAS)) {
                    keyStore.deleteEntry(LRU_TEST_ALIAS);
                }
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    public String description() {
        return "Keystore 2.0 LRU Pruning Anomaly (%d) - 操作驱逐异常，缺乏资源管理";
    }

    private static class OperationInfo {
        final Signature signature;
        final int index;

        OperationInfo(Signature signature, int index) {
            this.signature = signature;
            this.index = index;
        }
    }
}
