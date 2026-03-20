package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;

/**
 * Keystore 2.0 KeyMetadata KEY_ID 语义检测
 *
 * 检测原理：
 * - AOSP Keystore2 在 getKeyEntry() 返回结果中，会把 metadata.key 规范化为 KEY_ID 域
 * - 也就是说，返回的 KeyDescriptor 不再是原始 APP/alias 形式，而是 Domain.KEY_ID + nspace
 * - 某些 Hook/模拟实现为了伪造 KeyMetadata，会直接把原始 descriptor 塞回 metadata.key
 * - 这会导致返回值语义与 AOSP 不一致
 *
 * 检测方法：
 * 1. 生成一个测试密钥
 * 2. 直接调用 IKeystoreService.getKeyEntry()
 * 3. 读取返回结果中的 metadata.key
 * 4. 检查其 domain 是否为 KEY_ID，alias 是否已经被清空
 *
 * 判定规则：
 * - 若 metadata.key.domain 不是 KEY_ID，或者 alias 仍然非空，则判定异常
 *
 * 检测目标：
 * - TEESimulator 软件生成密钥后的 fake KeyMetadata 返回路径
 * - 其他未正确模拟 AOSP KEY_ID 语义的 Hook/仿真实现
 */
public final class KeyIdMetadataChecker extends Checker {
    private static final String TAG = "KeyIdMetadataChecker";
    private static final String TEST_ALIAS = "KeyDetector_KeyId";

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
            cleanupAlias(keyStore);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            kpg.initialize(new KeyGenParameterSpec.Builder(TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kpg.generateKeyPair();

            Object service = Reflection.getIKeystoreService();
            Object keyEntryResponse = Reflection.getKeyEntry(service, Reflection.createKeyDescriptor(TEST_ALIAS));
            Object returnedDescriptor = Reflection.getReturnedKeyDescriptor(keyEntryResponse);

            int domain = Reflection.getIntField(returnedDescriptor, "domain");
            String alias = Reflection.getStringField(returnedDescriptor, "alias");

            if (domain != Reflection.getDomainKeyId() || alias != null) {
                Log.e(
                        TAG,
                        "ANOMALY: KeyMetadata.key is not normalized to KEY_ID. "
                                + "domain="
                                + domain
                                + " expected="
                                + Reflection.getDomainKeyId()
                                + " alias="
                                + alias);
                return true;
            }

            Log.d(TAG, "Check passed: KeyMetadata.key uses KEY_ID semantics.");
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "Check failed", t);
            return false;
        } finally {
            cleanupAlias(keyStore);
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
        return "KeyMetadata KEY_ID Semantics Anomaly (%d) - getKeyEntry 返回的 metadata.key 不是 KEY_ID";
    }
}
