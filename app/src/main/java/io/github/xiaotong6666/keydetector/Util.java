package io.github.xiaotong6666.keydetector;

import static io.github.xiaotong6666.keydetector.Constant.GOOGLE_ROOT_F;
import static io.github.xiaotong6666.keydetector.Constant.GOOGLE_ROOT_G;
import static io.github.xiaotong6666.keydetector.Constant.GOOGLE_ROOT_H;
import static io.github.xiaotong6666.keydetector.Constant.GOOGLE_ROOT_I;
import static io.github.xiaotong6666.keydetector.Constant.KEYSTORE_PROVIDER;
import static io.github.xiaotong6666.keydetector.Constant.KEY_ALIAS;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_AOSP;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_GOOGLE_F;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_GOOGLE_I;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_UNKNOWN;
import static io.github.xiaotong6666.keydetector.Constant.ROOT_VENDOR_REQUIRED;
import static io.github.xiaotong6666.keydetector.Constant.VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import io.github.xiaotong6666.keydetector.handler.BinderHookHandler;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

public class Util {
    public static int classifyRootType(X509Certificate rootCert) {
        if (rootCert == null) return ROOT_UNKNOWN;
        byte[] key = rootCert.getPublicKey().getEncoded();
        if (Arrays.equals(key, GOOGLE_ROOT_F)) return ROOT_GOOGLE_F;
        if (Arrays.equals(key, GOOGLE_ROOT_G) || Arrays.equals(key, GOOGLE_ROOT_H)) return ROOT_AOSP;
        if (Arrays.equals(key, GOOGLE_ROOT_I)) return ROOT_GOOGLE_I;
        String keyB64 = Base64.encodeToString(key, Base64.NO_WRAP);
        return VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64.contains(keyB64) ? ROOT_VENDOR_REQUIRED : ROOT_UNKNOWN;
    }

    @SuppressLint("PrivateApi")
    public static String getSystemProperty(String key) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method m = c.getDeclaredMethod("get", String.class);
            return (String) m.invoke(null, key);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] hexStringToByteArray(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex string is null");
        String s = hex.trim();
        if ((s.length() & 1) != 0)
            throw new IllegalArgumentException("hex string must have even length: " + s.length());
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) throw new IllegalArgumentException("invalid hex char at position " + i);
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String byteArrayToHexString(byte[] data) {
        if (data == null) throw new IllegalArgumentException("byte array is null");
        char[] out = new char[data.length * 2];
        final char[] HEX = "0123456789abcdef".toCharArray();
        int i = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            out[i++] = HEX[v >>> 4];
            out[i++] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    static CheckerContext getCheckerContext(Context appContext) {
        Security.removeProvider("BC");
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                HiddenApiBypass.addHiddenApiExemptions("");
            }
        } catch (Throwable t) {
            Log.w("Util", "HiddenApiBypass failed", t);
        }
        BinderHookHandler.installHook();
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            try {
                if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
            } catch (Exception ignored) {
            }
            byte[] challenge = java.util.UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateNotBefore(new Date())
                    .setAttestationChallenge(challenge);
            if (Build.VERSION.SDK_INT >= 31) builder.setAttestKeyAlias(null);
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            Certificate[] rawChain = keyStore.getCertificateChain(KEY_ALIAS);
            if (rawChain == null || rawChain.length < 2) return null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> sanitizedChain = new ArrayList<>();
            for (Certificate c : rawChain) {
                sanitizedChain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
            }
            return new CheckerContext(appContext, keyStore, sanitizedChain, challenge);
        } catch (Throwable t) {
            return null;
        }
    }

    public static byte[] randomChallenge(int size) {
        byte[] challenge = new byte[size];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }

    public static List<byte[]> buildFullChainBytes(byte[] leafDer, byte[] chainBlob) {
        List<byte[]> out = new ArrayList<>();
        if (leafDer == null) return out;
        out.add(leafDer);
        if (chainBlob == null || chainBlob.length == 0) return out;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(chainBlob));
            for (Certificate c : certs) {
                out.add(c.getEncoded());
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    public static List<byte[]> buildLegacyFullChainBytes(String alias) {
        List<byte[]> out = new ArrayList<>();
        if (alias == null) return out;

        byte[] userCert = BinderHookHandler.getLegacyKeystoreBlob("USRCERT_" + alias);
        byte[] caCert = BinderHookHandler.getLegacyKeystoreBlob("CACERT_" + alias);
        if (userCert == null && caCert == null) return out;

        if (userCert != null) {
            out.add(userCert);
        } else if (caCert != null) {
            out.add(caCert);
        }

        if (caCert != null && caCert.length > 0) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(caCert));
                for (Certificate c : certs) {
                    byte[] der = c.getEncoded();
                    if (!out.isEmpty() && Arrays.equals(out.get(0), der)) continue;
                    out.add(der);
                }
            } catch (Exception ignored) {
            }
        }

        return out;
    }

    public static boolean chainsEqualKeystoreVsDer(List<X509Certificate> keystoreChain, List<byte[]> otherChainDer) {
        if (keystoreChain == null || otherChainDer == null) return false;
        if (keystoreChain.size() != otherChainDer.size()) return false;
        try {
            for (int i = 0; i < keystoreChain.size(); i++) {
                if (!Arrays.equals(keystoreChain.get(i).getEncoded(), otherChainDer.get(i))) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean chainsEqualDer(List<byte[]> a, List<byte[]> b) {
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) return false;
        }
        return true;
    }

    public static String describeChainMismatch(List<X509Certificate> keystoreChain, List<byte[]> otherChainDer) {
        if (keystoreChain == null || otherChainDer == null) {
            return "keystore="
                    + (keystoreChain == null ? "null" : "non-null")
                    + " binder="
                    + (otherChainDer == null ? "null" : "non-null");
        }
        int min = Math.min(keystoreChain.size(), otherChainDer.size());
        for (int i = 0; i < min; i++) {
            try {
                byte[] a = keystoreChain.get(i).getEncoded();
                byte[] b = otherChainDer.get(i);
                if (!Arrays.equals(a, b)) {
                    return "mismatchIndex="
                            + i
                            + " keystoreSerial="
                            + keystoreChain
                                    .get(i)
                                    .getSerialNumber()
                                    .toString(16)
                                    .toLowerCase(Locale.US)
                            + " binderSerial="
                            + tryGetSerialHex(b);
                }
            } catch (Throwable ignored) {
                return "mismatchIndex=" + i + " (encode/parse failed)";
            }
        }
        if (keystoreChain.size() != otherChainDer.size()) {
            return "lengthMismatch keystore=" + keystoreChain.size() + " binder=" + otherChainDer.size();
        }
        return "unknown";
    }

    public static String tryGetSerialHex(byte[] certDer) {
        if (certDer == null || certDer.length == 0) return "null";
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
            return cert.getSerialNumber().toString(16).toLowerCase(Locale.US);
        } catch (Throwable t) {
            return "parse_failed";
        }
    }

    public static void logChain(String label, List<X509Certificate> chain) {
        if (chain == null) {
            Log.e("KeyDetector", label + ": null");
            return;
        }
        Log.e("KeyDetector", label + ": size=" + chain.size());
        for (int i = 0; i < chain.size(); i++) {
            logCert(label + "[" + i + "]", chain.get(i));
        }
    }

    public static void logCert(String label, X509Certificate cert) {
        if (cert == null) {
            Log.e("KeyDetector", label + ": null");
            return;
        }
        try {
            Log.e(
                    "KeyDetector",
                    label
                            + " serialHex="
                            + cert.getSerialNumber().toString(16).toLowerCase(Locale.US)
                            + " sigAlg="
                            + cert.getSigAlgName()
                            + " pubKeyAlg="
                            + cert.getPublicKey().getAlgorithm()
                            + " notBefore="
                            + cert.getNotBefore()
                            + " notAfter="
                            + cert.getNotAfter());
            Log.e("KeyDetector", label + " subject=" + cert.getSubjectX500Principal());
            Log.e("KeyDetector", label + " issuer=" + cert.getIssuerX500Principal());
        } catch (Throwable t) {
            Log.e("KeyDetector", label + ": failed to log certificate details", t);
        }
    }
}
