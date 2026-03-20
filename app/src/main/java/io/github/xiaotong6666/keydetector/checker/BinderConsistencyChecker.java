package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;
import static io.github.xiaotong6666.keydetector.Constant.KEY_ALIAS;
import static io.github.xiaotong6666.keydetector.Util.buildFullChainBytes;
import static io.github.xiaotong6666.keydetector.Util.buildLegacyFullChainBytes;
import static io.github.xiaotong6666.keydetector.Util.chainsEqualDer;
import static io.github.xiaotong6666.keydetector.Util.chainsEqualKeystoreVsDer;
import static io.github.xiaotong6666.keydetector.Util.describeChainMismatch;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.handler.BinderHookHandler;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public final class BinderConsistencyChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        boolean failure = false;
        boolean hookInstalled = BinderHookHandler.isHookSuccess();

        if (hookInstalled) {
            if (ctx.certChain.size() >= 2) {
                byte[] leafSpki = ctx.certChain.get(0).getPublicKey().getEncoded();
                byte[] issuerSpki = ctx.certChain.get(1).getPublicKey().getEncoded();
                if (Arrays.equals(leafSpki, issuerSpki)) {
                    Log.e("BinderConsistency", "Suspicious chain: leaf public key equals issuer public key");
                    failure = true;
                }
            }

            byte[] binderKeyEntryLeaf = BinderHookHandler.getKeyEntryLeafCertificate(KEY_ALIAS);
            byte[] binderKeyEntryChainBlob = BinderHookHandler.getKeyEntryCertificateChainBlob(KEY_ALIAS);

            List<byte[]> binderKeyEntryFull;
            if (binderKeyEntryLeaf != null) {
                binderKeyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
            } else {
                binderKeyEntryFull = buildLegacyFullChainBytes(KEY_ALIAS);
            }

            if (binderKeyEntryFull == null || binderKeyEntryFull.isEmpty()) {
                Log.e("BinderConsistency", "No binder-captured certificate data found (keystore2/legacy)");
                failure = true;
            } else if (!chainsEqualKeystoreVsDer(ctx.certChain, binderKeyEntryFull)) {
                Log.e(
                        "BinderConsistency",
                        "Keystore chain differs from Binder chain: "
                                + describeChainMismatch(ctx.certChain, binderKeyEntryFull));
                failure = true;
            }
        }

        if (runActiveKeyProbe(hookInstalled)) {
            failure = true;
        }

        return failure;
    }

    private boolean runActiveKeyProbe(boolean hookInstalled) {
        final String alias = "KeyDetector";
        try {
            if (!generateAndSignProbeKey(alias)) return true;
            if (checkProbeKeyConsistency(alias, hookInstalled)) return true;

            if (!generateAndSignProbeKey(alias)) {
                return true;
            } else {
                if (checkProbeKeyConsistency(alias, hookInstalled)) return true;
            }

            return deleteEntryAndVerifyRemoved(alias);
        } catch (Throwable t) {
            Log.e("BinderConsistency", "Active key probe crashed", t);
            return true;
        }
    }

    private boolean generateAndSignProbeKey(String alias) {
        try {
            Date now = new Date();
            byte[] challenge = now.toString().getBytes(StandardCharsets.UTF_8);

            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateNotBefore(now)
                    .setAttestationChallenge(challenge);

            if (Build.VERSION.SDK_INT >= 31) {
                builder.setAttestKeyAlias(null);
            }

            keyPairGenerator.initialize(builder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(challenge);
            signature.sign();
            return true;
        } catch (Throwable t) {
            Log.e("BinderConsistency", "Active probe key generation/sign failed: alias=" + alias, t);
            return false;
        }
    }

    private boolean checkProbeKeyConsistency(String alias, boolean hookInstalled) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            Certificate[] rawChain = keyStore.getCertificateChain(alias);
            if (rawChain == null || rawChain.length < 2) {
                Log.e("BinderConsistency", "Active probe getCertificateChain returned invalid chain for " + alias);
                return true;
            }

            if (!hookInstalled) {
                return false;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> sanitizedChain = new ArrayList<>();
            for (Certificate c : rawChain) {
                sanitizedChain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
            }

            return checkProbeKeyBinderConsistency(alias, sanitizedChain);
        } catch (Throwable t) {
            Log.e("BinderConsistency", "Active probe chain check failed: alias=" + alias, t);
            return true;
        }
    }

    private boolean checkProbeKeyBinderConsistency(String alias, List<X509Certificate> keystoreChain) {
        if (alias == null || keystoreChain == null || keystoreChain.isEmpty()) return true;

        try {
            if (keystoreChain.size() >= 2) {
                byte[] leafSpki = keystoreChain.get(0).getPublicKey().getEncoded();
                byte[] issuerSpki = keystoreChain.get(1).getPublicKey().getEncoded();
                if (Arrays.equals(leafSpki, issuerSpki)) {
                    Log.e("BinderConsistency", "Active probe: suspicious chain (leaf SPKI equals issuer SPKI)");
                    return true;
                }
            }

            byte[] binderKeyEntryLeaf = BinderHookHandler.getKeyEntryLeafCertificate(alias);
            byte[] binderKeyEntryChainBlob = BinderHookHandler.getKeyEntryCertificateChainBlob(alias);

            List<byte[]> binderKeyEntryFull;
            if (binderKeyEntryLeaf != null) {
                binderKeyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
            } else {
                binderKeyEntryFull = buildLegacyFullChainBytes(alias);
            }

            if (binderKeyEntryFull == null || binderKeyEntryFull.isEmpty()) {
                Log.e("BinderConsistency", "Active probe: no binder-captured certificate data found");
                return true;
            }
            if (!chainsEqualKeystoreVsDer(keystoreChain, binderKeyEntryFull)) {
                Log.e(
                        "BinderConsistency",
                        "Active probe: keystore chain differs from binder chain: "
                                + describeChainMismatch(keystoreChain, binderKeyEntryFull));
                return true;
            }

            byte[] binderGenerateLeaf = BinderHookHandler.getGenerateKeyLeafCertificate(alias);
            if (binderGenerateLeaf == null) {
                Log.e("BinderConsistency", "Active probe: missing binder-captured generateKey certificate");
                return true;
            }

            byte[] referenceLeaf = binderKeyEntryLeaf != null
                    ? binderKeyEntryLeaf
                    : keystoreChain.get(0).getEncoded();
            if (!Arrays.equals(binderGenerateLeaf, referenceLeaf)) {
                Log.e(
                        "BinderConsistency",
                        "Active probe: leaf certificate differs between generateKey and getKeyEntry");
                return true;
            }

            if (binderKeyEntryLeaf != null) {
                byte[] binderGenerateChainBlob = BinderHookHandler.getGenerateKeyCertificateChainBlob(alias);
                List<byte[]> genFull = buildFullChainBytes(binderGenerateLeaf, binderGenerateChainBlob);
                List<byte[]> keyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
                if (!genFull.isEmpty() && !keyEntryFull.isEmpty() && !chainsEqualDer(genFull, keyEntryFull)) {
                    Log.e("BinderConsistency", "Active probe: chain differs between generateKey and getKeyEntry");
                    return true;
                }
            }
        } catch (Throwable t) {
            Log.w("BinderConsistency", "Active probe binder consistency check failed", t);
            return true;
        }

        return false;
    }

    private boolean deleteEntryAndVerifyRemoved(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(alias)) {
                return false;
            }

            keyStore.deleteEntry(alias);

            KeyStore verifyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            verifyStore.load(null);
            if (verifyStore.containsAlias(alias)) {
                Log.e("BinderConsistency", "Active probe deleteEntry did not remove alias: " + alias);
                return true;
            }

            return false;
        } catch (Throwable t) {
            Log.e("BinderConsistency", "Active probe deleteEntry failed: alias=" + alias, t);
            return true;
        }
    }

    @Override
    public String description() {
        return "Tampered/Inconsistent Key (%d)\nKeyStore 证书链与 Binder 捕获不一致，或 Active Probe 失败";
    }
}
