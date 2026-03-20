package com.xiaotong.keydetector.checker;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * TEE 加密性能检测
 *
 * 检测原理：
 * - 使用 AndroidKeyStore AES 密钥执行多轮加密与生钥测试
 * - 对照经验阈值判断性能是否明显异常
 *
 * 判定规则：
 * - 若平均加密或生钥耗时明显高于经验阈值，视为异常
 */
public final class TeeEncryptionPerformanceChecker extends Checker {
    private static final String TAG = "TeePerfChecker";
    private static final String TEST_ALIAS = "KeyDetector_Perf";
    private static final int SMALL_ITERATIONS = 10;
    private static final int MEDIUM_ITERATIONS = 5;
    private static final int LARGE_ITERATIONS = 3;
    private static final int KEYGEN_ITERATIONS = 3;

    private static final double SMALL_THRESHOLD_MS = 10.0;
    private static final double MEDIUM_THRESHOLD_MS = 50.0;
    private static final double LARGE_THRESHOLD_MS = 200.0;
    private static final double KEYGEN_THRESHOLD_MS = 1000.0;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            cleanupAlias(keyStore, TEST_ALIAS);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                            TEST_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(256)
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

            SecretKey secretKey = (SecretKey) keyStore.getKey(TEST_ALIAS, null);
            if (secretKey == null) {
                return false;
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] smallData = "small_test".getBytes();
            byte[] mediumData = new byte[512];
            byte[] largeData = new byte[2048];

            double avgSmallTime = measureAverageEncryptMs(cipher, secretKey, smallData, SMALL_ITERATIONS);
            double avgMediumTime = measureAverageEncryptMs(cipher, secretKey, mediumData, MEDIUM_ITERATIONS);
            double avgLargeTime = measureAverageEncryptMs(cipher, secretKey, largeData, LARGE_ITERATIONS);
            double avgKeyGenTime = measureAverageKeyGenMs(keyStore);

            boolean performanceAcceptable = avgSmallTime < SMALL_THRESHOLD_MS * 2
                    && avgMediumTime < MEDIUM_THRESHOLD_MS * 2
                    && avgLargeTime < LARGE_THRESHOLD_MS * 2
                    && avgKeyGenTime < KEYGEN_THRESHOLD_MS * 2;

            if (!performanceAcceptable) {
                Log.e(
                        TAG,
                        "ANOMALY: keystore performance degraded"
                                + " smallMs="
                                + avgSmallTime
                                + " mediumMs="
                                + avgMediumTime
                                + " largeMs="
                                + avgLargeTime
                                + " keyGenMs="
                                + avgKeyGenTime);
                return true;
            }

            return false;
        } catch (Exception e) {
            Log.w(TAG, "Check failed", e);
            return false;
        } finally {
            if (keyStore != null) {
                cleanupAlias(keyStore, TEST_ALIAS);
                for (int i = 0; i < KEYGEN_ITERATIONS; i++) {
                    cleanupAlias(keyStore, TEST_ALIAS + "_" + i);
                }
            }
        }
    }

    private double measureAverageEncryptMs(Cipher cipher, SecretKey secretKey, byte[] data, int iterations)
            throws Exception {
        long totalNanos = 0L;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            cipher.doFinal(data);
            totalNanos += System.nanoTime() - start;
        }
        return (totalNanos / (double) iterations) / 1_000_000.0;
    }

    private double measureAverageKeyGenMs(KeyStore keyStore) throws Exception {
        long totalNanos = 0L;
        for (int i = 0; i < KEYGEN_ITERATIONS; i++) {
            String alias = TEST_ALIAS + "_" + i;
            cleanupAlias(keyStore, alias);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                            alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(256)
                    .build();
            long start = System.nanoTime();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
            totalNanos += System.nanoTime() - start;
        }
        return (totalNanos / (double) KEYGEN_ITERATIONS) / 1_000_000.0;
    }

    private void cleanupAlias(KeyStore keyStore, String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public String description() {
        return "TEE Encryption Performance Anomaly (%d)\nAndroidKeyStore 加密或生钥性能明显异常";
    }
}
