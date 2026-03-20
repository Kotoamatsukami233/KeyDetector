package io.github.xiaotong6666.keydetector.checker;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class BouncyCastleChainChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        return !verifyChainWithBouncyCastle(ctx.certChain);
    }

    private boolean verifyChainWithBouncyCastle(List<X509Certificate> chain) {
        try {
            java.security.Provider bcProvider = Security.getProvider("BC");
            if (bcProvider == null) {
                bcProvider = new BouncyCastleProvider();
            }
            X509Certificate root = chain.get(chain.size() - 1);
            try {
                root.checkValidity();
                root.verify(root.getPublicKey(), bcProvider);
            } catch (Exception e) {
                Log.e("BouncyCastleChainChecker", "BC: Root verify failed", e);
                return false;
            }
            PublicKey parentKey = root.getPublicKey();
            for (int i = chain.size() - 2; i >= 0; i--) {
                X509Certificate current = chain.get(i);
                try {
                    current.checkValidity();
                    current.verify(parentKey, bcProvider);
                } catch (GeneralSecurityException e) {
                    Log.e("BouncyCastleChainChecker", "BC: Signature verification failed at index " + i, e);
                    return false;
                }
                parentKey = current.getPublicKey();
            }
            return true;
        } catch (Exception e) {
            Log.e("BouncyCastleChainChecker", "BC: Chain verification error", e);
            return false;
        }
    }

    @Override
    public String description() {
        return "Broken Chain (%d)\n证书链签名验证失败，疑似中间人篡改";
    }
}
