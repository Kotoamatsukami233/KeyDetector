package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEY_ALIAS;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.Util;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class KeyConsistencyChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        KeyStore.Entry entry = ctx.keyStore.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) throw new Exception("Entry is not a PrivateKeyEntry");
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        PublicKey publicKey = ctx.certChain.get(0).getPublicKey();
        byte[] data = "ConsistencyCheck".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        java.security.Provider bcProvider = Security.getProvider("BC");
        if (bcProvider == null) bcProvider = new BouncyCastleProvider();
        Signature verifier = Signature.getInstance("SHA256withECDSA", bcProvider);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean ok = verifier.verify(signature);
        if (!ok) {
            Log.e(
                    "Detector",
                    "Key consistency failed: certificate public key cannot verify keystore private-key signature.");
            Util.logCert("Leaf", ctx.certChain.get(0));
        }
        return !ok;
    }

    @Override
    public String description() {
        return "Key Mismatch (%d)\n私钥与证书公钥不匹配，严重的欺诈行为";
    }
}
