package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Util.randomChallenge;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.KeyPairGenerator;

public final class AttestationComplianceChecker extends Checker {
    private static final short CHALLENGE_LENGTH = 256;
    private static final String TEST_ALIAS = "attestation_test_256";
    private static final String TAG = "AttestComplianceChk";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        byte[] challenge = randomChallenge(CHALLENGE_LENGTH);
        Log.d(TAG, "Starting compliance probe: alias=" + TEST_ALIAS + ", challengeLength=" + challenge.length);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                            TEST_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build();
            kpg.initialize(spec);
            kpg.generateKeyPair();
            Log.e(TAG, "ANOMALY: AndroidKeyStore accepted overlong attestation challenge, length=" + challenge.length);
            return true;
        } catch (Exception e) {
            Log.d(
                    TAG,
                    "Compliance probe rejected overlong challenge as expected: "
                            + e.getClass().getSimpleName());
            return false;
        }
    }

    @Override
    public String description() {
        return "Non-compliant Keystore Detected (%d)\n检测到不规范的 KeyStore , Challenge 长度不应该允许为 "
                + Integer.toString(CHALLENGE_LENGTH);
    }
}
