package com.xiaotong.keydetector.checker;

import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * 生物识别 TEE 集成检测
 *
 * 检测原理：
 * - 仅在设备存在生物识别硬件时运行
 * - 若系统报告强生物识别能力可用，则进一步尝试创建需用户认证的 Keystore 密钥
 * - 以此验证生物识别与受保护密钥路径的集成是否正常
 *
 * 判定规则：
 * - 无生物识别硬件或生物识别当前不可用时不报异常
 * - 若强生物识别可用，但无法创建或取回需认证的密钥，视为异常
 */
public final class BiometricTeeIntegrationChecker extends Checker {
    private static final String TAG = "BiometricTeeChecker";
    private static final String TEST_ALIAS = "KeyDetector_Biometric";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }

        PackageManager packageManager = ctx.appContext.getPackageManager();
        boolean hasBiometricHardware = packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
                || packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)
                || packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS);
        if (!hasBiometricHardware) {
            return false;
        }

        boolean strongBiometricAvailable = false;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                BiometricManager biometricManager = ctx.appContext.getSystemService(BiometricManager.class);
                if (biometricManager != null) {
                    int status = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
                    strongBiometricAvailable = status == BiometricManager.BIOMETRIC_SUCCESS;
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                BiometricManager biometricManager = ctx.appContext.getSystemService(BiometricManager.class);
                if (biometricManager != null) {
                    strongBiometricAvailable = biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "BiometricManager check failed", e);
        }

        if (!strongBiometricAvailable) {
            return false;
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            cleanupAlias(keyStore);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                            TEST_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(30)
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

            SecretKey secretKey = (SecretKey) keyStore.getKey(TEST_ALIAS, null);
            if (secretKey == null) {
                Log.e(TAG, "ANOMALY: strong biometric is available but biometric-protected key cannot be retrieved");
                return true;
            }

            return false;
        } catch (Exception e) {
            Log.e(TAG, "ANOMALY: strong biometric is available but biometric-protected key creation failed", e);
            return true;
        } finally {
            if (keyStore != null) {
                cleanupAlias(keyStore);
            }
        }
    }

    private void cleanupAlias(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(TEST_ALIAS)) {
                keyStore.deleteEntry(TEST_ALIAS);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public String description() {
        return "Biometric TEE Integration Anomaly (%d)\n强生物识别可用，但生物识别保护密钥创建失败";
    }
}
