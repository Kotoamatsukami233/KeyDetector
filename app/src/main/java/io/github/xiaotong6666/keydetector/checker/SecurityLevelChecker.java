package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.cert.Certificate;

public final class SecurityLevelChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_PureCert";

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
            if (ctx.certChain == null || ctx.certChain.isEmpty()) return false;
            Certificate cert = ctx.certChain.get(0);

            keyStore.setCertificateEntry(TEST_ALIAS, cert);
        } catch (Exception e) {
            return false;
        }

        try {
            Object service = Reflection.getIKeystoreService();
            Object keyDescriptor = Reflection.createKeyDescriptor(TEST_ALIAS);

            Method getKeyEntryMethod = service.getClass().getMethod("getKeyEntry", keyDescriptor.getClass());
            Object keyEntryResponse = getKeyEntryMethod.invoke(service, keyDescriptor);

            if (keyEntryResponse != null) {
                Field securityLevelField = keyEntryResponse.getClass().getField("iSecurityLevel");
                Object iSecurityLevel = securityLevelField.get(keyEntryResponse);

                if (iSecurityLevel != null) {
                    Log.e(
                            "Keystore2SecurityLevel",
                            "Anomaly: Pure certificate entry has iSecurityLevel populated (" + iSecurityLevel + ")");
                    return true;
                }
            }

        } catch (Throwable t) {
            Log.w("Keystore2SecurityLevel", "Check failed", t);
        } finally {
            try {
                keyStore.deleteEntry(TEST_ALIAS);
            } catch (Exception ignored) {
            }
        }

        return false;
    }

    @Override
    public String description() {
        return "Keystore 2.0 SecurityLevel Anomaly (%d) - 纯证书条目错误返回 SecurityLevel";
    }
}
