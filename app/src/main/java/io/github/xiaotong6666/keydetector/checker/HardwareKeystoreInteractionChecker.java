package io.github.xiaotong6666.keydetector.checker;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 硬件密钥存储交互检测
 *
 * 检测原理：
 * - 生成 AndroidKeyStore AES 密钥并取回
 * - 使用 KeyInfo.isInsideSecureHardware 检查密钥是否位于安全硬件
 * - 执行一次 AES-GCM 加解密往返，验证硬件密钥交互路径是否正常
 *
 * 判定规则：
 * - 密钥无法生成或取回，视为异常
 * - 密钥不在安全硬件中，视为异常
 * - 加解密往返失败，视为异常
 */
public final class HardwareKeystoreInteractionChecker extends Checker {
    private static final String TAG = "HwKeystoreChecker";
    private static final String TEST_ALIAS = "KeyDetector_Tee_Aes";

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
            cleanupAlias(keyStore);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                            TEST_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

            SecretKey retrievedKey = (SecretKey) keyStore.getKey(TEST_ALIAS, null);
            if (retrievedKey == null) {
                Log.e(TAG, "ANOMALY: generated AES key could not be retrieved from AndroidKeyStore");
                return true;
            }

            boolean isHardwareBacked;
            try {
                SecretKeyFactory keyFactory =
                        SecretKeyFactory.getInstance(retrievedKey.getAlgorithm(), "AndroidKeyStore");
                KeyInfo keyInfo = (KeyInfo) keyFactory.getKeySpec(retrievedKey, KeyInfo.class);
                isHardwareBacked = keyInfo.isInsideSecureHardware();
            } catch (Exception e) {
                Log.e(TAG, "ANOMALY: failed to read KeyInfo for AES key", e);
                return true;
            }

            if (!isHardwareBacked) {
                Log.e(TAG, "ANOMALY: AES key is not stored inside secure hardware");
                return true;
            }

            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                byte[] testData = "TEE_test_data".getBytes();
                cipher.init(Cipher.ENCRYPT_MODE, retrievedKey);
                byte[] encrypted = cipher.doFinal(testData);
                byte[] iv = cipher.getIV();
                cipher.init(Cipher.DECRYPT_MODE, retrievedKey, new GCMParameterSpec(128, iv));
                byte[] decrypted = cipher.doFinal(encrypted);
                if (!java.util.Arrays.equals(testData, decrypted)) {
                    Log.e(TAG, "ANOMALY: AES-GCM round-trip with hardware keystore key failed");
                    return true;
                }
            } catch (Exception e) {
                Log.e(TAG, "ANOMALY: AES-GCM interaction with hardware keystore failed", e);
                return true;
            }

            return false;
        } catch (Exception e) {
            Log.w(TAG, "Check failed", e);
            return false;
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
        return "Hardware Keystore Interaction Anomaly (%d)\nAES 密钥未进入安全硬件或硬件密钥交互失败";
    }
}
