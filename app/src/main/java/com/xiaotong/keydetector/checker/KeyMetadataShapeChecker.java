package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Keystore 2.0 KeyMetadata 结构完整性检测
 *
 * 检测原理：
 * - AOSP Keystore2 返回 KeyMetadata 时，会填充系统生成的元数据字段
 * - 其中 modificationTimeMs 来自数据库记录，authorizations 来自持久化的 key parameters
 * - 对正常生成的密钥，authorizations 中通常至少应包含 ORIGIN 等基础系统标签
 * - 某些 Hook/模拟实现只伪造了最少量字段，遗漏 modificationTimeMs 或 ORIGIN
 *
 * 检测方法：
 * 1. 生成一个测试密钥
 * 2. 直接调用 IKeystoreService.getKeyEntry()
 * 3. 读取返回的 KeyMetadata.modificationTimeMs
 * 4. 遍历 KeyMetadata.authorizations，收集其中的 tag
 * 5. 检查 modificationTimeMs 和 ORIGIN 是否存在
 *
 * 判定规则：
 * - modificationTimeMs <= 0 视为异常
 * - authorizations 中缺少 ORIGIN 视为异常
 *
 * 检测目标：
 * - TEESimulator 伪造 KeyMetadata 时遗漏系统字段的情况
 * - 其他只模拟证书链但没有完整模拟 metadata/auths 的 Hook 实现
 */
public final class KeyMetadataShapeChecker extends Checker {
    private static final String TAG = "KeyMetadataShapeChecker";
    private static final String TEST_ALIAS = "KeyDetector_Metadata";

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
            Object metadata = Reflection.getMetadata(keyEntryResponse);

            long modificationTimeMs = Reflection.getLongField(metadata, "modificationTimeMs");
            Set<Integer> tags = collectAuthorizationTags(metadata);
            List<String> missing = new ArrayList<>();

            if (modificationTimeMs <= 0) {
                missing.add("modificationTimeMs<=0");
            }
            if (!tags.contains(Reflection.getTag("ORIGIN"))) {
                missing.add("ORIGIN");
            }
            if (!missing.isEmpty()) {
                Log.e(
                        TAG,
                        "ANOMALY: KeyMetadata shape mismatch. Missing/invalid fields="
                                + missing
                                + " authCount="
                                + tags.size()
                                + " modificationTimeMs="
                                + modificationTimeMs);
                return true;
            }

            Log.d(TAG, "Check passed: KeyMetadata contains expected system-populated fields.");
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "Check failed", t);
            return false;
        } finally {
            cleanupAlias(keyStore);
        }
    }

    private Set<Integer> collectAuthorizationTags(Object metadata) throws Exception {
        Set<Integer> tags = new HashSet<>();
        Object[] authorizations = Reflection.toObjectArray(Reflection.getFieldValue(metadata, "authorizations"));
        for (Object authorization : authorizations) {
            if (authorization == null) {
                continue;
            }
            Object keyParameter = Reflection.getFieldValue(authorization, "keyParameter");
            if (keyParameter == null) {
                continue;
            }
            tags.add(Reflection.getIntField(keyParameter, "tag"));
        }
        return tags;
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
        return "KeyMetadata Shape Anomaly (%d) - modificationTimeMs / ORIGIN 返回异常";
    }
}
