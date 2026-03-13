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
import java.util.List;
import java.util.UUID;

/**
 * Keystore 2.0 ListEntriesBatched 分页语义检测
 *
 * 检测原理：
 * - Android 14+ 新增 IKeystoreService.listEntriesBatched(domain, namespace, startPastAlias)
 * - AOSP 语义要求：返回 alias 严格大于 startPastAlias 的条目，且结果按 alias 升序排序
 * - 某些 Hook/模拟实现虽然拦截了 listEntriesBatched，但可能把分页游标语义实现错
 * - 典型错误是把 “alias > startPastAlias” 写成 “alias < startPastAlias”
 *
 * 检测方法：
 * 1. 仅在 Android 14+ 上启用检测
 * 2. 动态生成一对随机测试别名：zzzz_<uuid>_0 和 zzzz_<uuid>_1
 * 3. 以 zzzz_<uuid>_0 作为 startPastAlias 调用 listEntriesBatched()
 * 4. 检查返回结果中是否仍然包含 cursor 自身，或缺少紧随其后的测试别名
 *
 * 判定规则：
 * - 强异常：返回结果仍包含 cursor 自身 alias，明显违背 AOSP 的 startPastAlias 语义
 * - 中等异常：返回结果不包含紧随 cursor 之后的测试 alias，说明分页实现可能异常
 *
 * 检测目标：
 * - TEESimulator 的 listEntriesBatched 实现偏差
 * - 其他仿照 AOSP 接口但分页游标处理错误的 Hook/模拟实现
 */
public final class ListEntriesBatchedChecker extends Checker {
    private static final String TAG = "ListEntriesBatchedChecker";
    private static final String STRONG_SEVERITY = "强异常";
    private static final String MEDIUM_SEVERITY = "中等异常";
    private static final String PASS_SEVERITY = "未命中";
    private volatile String lastSeverity = PASS_SEVERITY;
    private volatile String lastSummary = "未发现 startPastAlias 分页语义异常";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        resetResult();
        if (Build.VERSION.SDK_INT < 34) {
            Log.d(TAG, "Skipping check: listEntriesBatched is only available on Android 14+.");
            return false;
        }

        String aliasPrefix = "zzzz_" + UUID.randomUUID().toString().replace("-", "");
        String testAliasA = aliasPrefix + "_0";
        String testAliasB = aliasPrefix + "_1";
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            cleanupAlias(keyStore, testAliasA);
            cleanupAlias(keyStore, testAliasB);

            generateSigningKey(testAliasA);
            generateSigningKey(testAliasB);

            Object service = Reflection.getIKeystoreService();
            Object result = Reflection.listEntriesBatched(service, testAliasA);
            List<String> aliases = extractAliases(result);

            boolean containsA = aliases.contains(testAliasA);
            boolean containsB = aliases.contains(testAliasB);

            if (containsA) {
                lastSeverity = STRONG_SEVERITY;
                lastSummary = "返回结果仍包含 cursor 自身 alias";
                Log.e(
                        TAG,
                        "ANOMALY[" + lastSeverity + "]: listEntriesBatched cursor semantics mismatch. "
                                + "cursor="
                                + testAliasA
                                + " containsA="
                                + containsA
                                + " containsB="
                                + containsB
                                + " aliases="
                                + aliases);
                return true;
            }

            if (!containsB) {
                lastSeverity = MEDIUM_SEVERITY;
                lastSummary = "startPastAlias 之后的探针 alias 未出现在结果中";
                Log.w(
                        TAG,
                        "ANOMALY[" + lastSeverity
                                + "]: listEntriesBatched did not include the probe alias after the cursor. "
                                + "cursor="
                                + testAliasA
                                + " expectedNext="
                                + testAliasB
                                + " aliases="
                                + aliases);
                return true;
            }

            Log.d(TAG, "Check passed: listEntriesBatched respects startPastAlias ordering.");
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "Check failed", t);
            return false;
        } finally {
            cleanupAlias(keyStore, testAliasA);
            cleanupAlias(keyStore, testAliasB);
        }
    }

    private void resetResult() {
        lastSeverity = PASS_SEVERITY;
        lastSummary = "未发现 startPastAlias 分页语义异常";
    }

    private void generateSigningKey(String alias) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        kpg.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        kpg.generateKeyPair();
    }

    private List<String> extractAliases(Object result) throws Exception {
        List<String> aliases = new ArrayList<>();
        for (Object descriptor : Reflection.toObjectArray(result)) {
            if (descriptor == null) {
                continue;
            }
            String alias = Reflection.getStringField(descriptor, "alias");
            if (alias != null) {
                aliases.add(alias);
            }
        }
        return aliases;
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
        return "IKeystoreService ListEntriesBatched Anomaly (%d) - " + lastSeverity + "：" + lastSummary;
    }
}
