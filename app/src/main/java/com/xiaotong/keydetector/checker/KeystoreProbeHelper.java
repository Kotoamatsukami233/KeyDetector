package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

final class KeystoreProbeHelper {
    private KeystoreProbeHelper() {}

    static KeyStore openKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);
        return keyStore;
    }

    static KeyGenParameterSpec.Builder newEcSigningKeyBuilder(String alias, int purposes) {
        return new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
    }

    static void generateEcKey(KeyGenParameterSpec.Builder builder) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        kpg.initialize(builder.build());
        kpg.generateKeyPair();
    }

    static Certificate[] getCertificateChain(KeyStore keyStore, String alias) throws Exception {
        return keyStore.getCertificateChain(alias);
    }

    static X509Certificate getLeafCertificate(KeyStore keyStore, String alias) throws Exception {
        Certificate[] chain = getCertificateChain(keyStore, alias);
        if (chain == null || chain.length == 0) {
            return null;
        }
        return (X509Certificate) chain[0];
    }

    static void cleanupAlias(KeyStore keyStore, String alias) {
        if (keyStore == null) {
            return;
        }
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        } catch (Exception ignored) {
        }
    }
}
