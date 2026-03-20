package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * Keystore 2.0 UpdateSubcomponent Checker
 *
 * 检测原理：
 * - Hook 框架（如 TEESimulator）拦截 generateKey()，创建虚假密钥（只在缓存中）
 * - Hook 框架通常不拦截 setKeyEntry()，或者不完整拦截
 * - setKeyEntry() 会触发 AndroidKeyStoreSpi.engineSetKeyEntry()
 * - 这会调用 IKeystoreService.updateSubcomponent()
 * - 真实的 Keystore2 找不到密钥，返回 KEY_NOT_FOUND 或证书更新失败
 *
 * 检测方法：
 * 1. 生成密钥（可能被 Hook 拦截）
 * 2. 获取密钥和证书链
 * 3. 调用 setKeyEntry() 尝试更新（触发 updateSubcomponent）
 * 4. 捕获异常并检查错误消息
 *
 * 检测目标：
 * - TrickyStore
 * - TEESimulator
 * - 其他不完整的 Hook 实现
 */
public final class UpdateSubcompChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_Subcomp";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < 31) {
            return false;
        }

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            kpg.initialize(new KeyGenParameterSpec.Builder(TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kpg.generateKeyPair();

            Certificate cert = keyStore.getCertificate(TEST_ALIAS);
            if (cert == null) {
                Log.w("Keystore2UpdateSubcomp", "Generated key but certificate is null");
                return false;
            }

            Key key = keyStore.getKey(TEST_ALIAS, null);
            Certificate[] chain = keyStore.getCertificateChain(TEST_ALIAS);

            if (key == null || chain == null || chain.length == 0) {
                Log.w("Keystore2UpdateSubcomp", "Could not retrieve key or certificate chain");
                return false;
            }

            try {
                keyStore.setKeyEntry(TEST_ALIAS, key, null, chain);
                Log.d("Keystore2UpdateSubcomp", "setKeyEntry succeeded - key exists in real Keystore2");
                return false;

            } catch (Exception e) {
                String message = e.getMessage();
                if (message == null) {
                    message = "";
                }

                boolean isKeyNotFound = message.contains("error 7")
                        || message.contains("KEY_NOT_FOUND")
                        || message.contains("key not found")
                        || message.contains("No key to update");

                boolean isCertError = message.contains("Couldn't insert certificate")
                        || message.contains("Failed to store certificate")
                        || (message.contains("certificate") && message.contains("fail"));

                if (isKeyNotFound) {
                    Log.e(
                            "Keystore2UpdateSubcomp",
                            "ANOMALY: updateSubcomponent KEY_NOT_FOUND - "
                                    + "Key generated via Java API but not found in real Keystore2. "
                                    + "Exception: "
                                    + e.getClass().getSimpleName()
                                    + ": "
                                    + message);
                    return true;
                }

                if (isCertError) {
                    Log.e(
                            "Keystore2UpdateSubcomp",
                            "ANOMALY: Certificate update failed - "
                                    + "Key exists in Hook cache but not in real Keystore2. "
                                    + "Exception: "
                                    + e.getClass().getSimpleName()
                                    + ": "
                                    + message);
                    return true;
                }

                Log.w(
                        "Keystore2UpdateSubcomp",
                        "setKeyEntry failed with unexpected error: "
                                + e.getClass().getSimpleName()
                                + ": "
                                + message);
                return false;
            }

        } catch (Exception e) {
            Log.w("Keystore2UpdateSubcomp", "Check failed", e);
            return false;
        } finally {
            try {
                if (keyStore.containsAlias(TEST_ALIAS)) {
                    keyStore.deleteEntry(TEST_ALIAS);
                }
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    public String description() {
        return "IKeystoreService UpdateSubcomponent Inconsistency (%d) - setKeyEntry 失败，密钥仅存在于缓存";
    }
}
