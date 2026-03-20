package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEY_ATTESTATION_OID;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

public final class ChallengeChecker extends Checker {
    private static final String TAG = "ChallengeChecker";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        final X509Certificate leafCert = ctx.certChain.get(0);
        final byte[] extBytes = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extBytes == null) {
            Log.d(TAG, "Skipping challenge compare: attestation extension missing on leaf certificate.");
            return false;
        }
        ASN1InputStream ais = new ASN1InputStream(extBytes);
        ASN1OctetString octet = (ASN1OctetString) ais.readObject();
        ais.close();
        ais = new ASN1InputStream(octet.getOctets());
        ASN1Sequence seq = (ASN1Sequence) ais.readObject();
        ais.close();
        ASN1OctetString challengeOctet = (ASN1OctetString) seq.getObjectAt(4);
        byte[] certChallenge = challengeOctet.getOctets();
        boolean matches = Arrays.equals(ctx.challenge, certChallenge);
        Log.d(
                TAG,
                "Comparing attestation challenge: requestedLength="
                        + (ctx.challenge != null ? ctx.challenge.length : -1)
                        + ", certificateLength="
                        + certChallenge.length
                        + ", requestedPrefix="
                        + shortHex(ctx.challenge)
                        + ", certificatePrefix="
                        + shortHex(certChallenge)
                        + ", matches="
                        + matches);
        if (!matches) {
            Log.e(TAG, "ANOMALY: attestation challenge in certificate does not match requested challenge.");
        }
        return !matches;
    }

    @Override
    public String description() {
        return "Attestation Challenge Mismatch (%d)\nAttestation Challenge 不匹配（可能重放）";
    }

    private static String shortHex(byte[] value) {
        if (value == null) return "null";
        int limit = Math.min(value.length, 8);
        StringBuilder sb = new StringBuilder(limit * 2 + (value.length > limit ? 3 : 0));
        for (int i = 0; i < limit; i++) {
            sb.append(String.format(Locale.US, "%02x", value[i] & 0xff));
        }
        if (value.length > limit) {
            sb.append("...");
        }
        return sb.toString();
    }
}
