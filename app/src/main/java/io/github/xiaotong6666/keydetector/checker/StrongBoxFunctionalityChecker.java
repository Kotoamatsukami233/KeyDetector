package io.github.xiaotong6666.keydetector.checker;

import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.lang.reflect.Method;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * StrongBox 功能检测
 *
 * 检测原理：
 * - 仅在系统声明支持 StrongBox 时运行
 * - 尝试生成 setIsStrongBoxBacked(true) 的密钥
 * - 再通过 KeyInfo 验证该密钥是否真的位于 StrongBox
 *
 * 判定规则：
 * - 设备未声明 StrongBox 支持时不报异常
 * - 若声明支持但无法生成 StrongBox key，视为异常
 * - 若生成后无法确认其为 StrongBox backed，视为异常
 */
public final class StrongBoxFunctionalityChecker extends Checker {
    private static final String TAG = "StrongBoxChecker";
    private static final String TEST_ALIAS = "KeyDetector_StrongBox";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false;
        }

        PackageManager packageManager = ctx.appContext.getPackageManager();
        if (!packageManager.hasSystemFeature("android.hardware.strongbox_keystore")) {
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
                    .setIsStrongBoxBacked(true)
                    .build();

            try {
                keyGenerator.init(keyGenParameterSpec);
                keyGenerator.generateKey();
            } catch (Exception e) {
                Log.e(TAG, "ANOMALY: device advertises StrongBox but StrongBox key generation failed", e);
                return true;
            }

            SecretKey secretKey = (SecretKey) keyStore.getKey(TEST_ALIAS, null);
            if (secretKey == null) {
                Log.e(TAG, "ANOMALY: StrongBox key was generated but cannot be retrieved");
                return true;
            }

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(secretKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = (KeyInfo) keyFactory.getKeySpec(secretKey, KeyInfo.class);
            boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();
            boolean isStrongBoxBacked = false;
            try {
                Method method = keyInfo.getClass().getMethod("isStrongBoxBacked");
                isStrongBoxBacked = (Boolean) method.invoke(keyInfo);
            } catch (Exception ignored) {
            }

            if (!(isInsideSecureHardware && isStrongBoxBacked)) {
                Log.e(
                        TAG,
                        "ANOMALY: device advertises StrongBox but generated key is not StrongBox-backed"
                                + " secureHardware="
                                + isInsideSecureHardware
                                + " strongBox="
                                + isStrongBoxBacked);
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
        return "StrongBox Functionality Anomaly (%d)\n系统声明支持 StrongBox，但密钥生成或验证失败";
    }
}
