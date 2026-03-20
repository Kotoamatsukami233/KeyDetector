package io.github.xiaotong6666.keydetector.checker;

import static io.github.xiaotong6666.keydetector.Constant.KEY_ALIAS;
import static io.github.xiaotong6666.keydetector.Util.buildFullChainBytes;
import static io.github.xiaotong6666.keydetector.Util.chainsEqualDer;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.handler.BinderHookHandler;
import java.util.Arrays;
import java.util.List;

public final class PatchModeChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        // 512
        byte[] binderGenerateLeaf = BinderHookHandler.getGenerateKeyLeafCertificate(KEY_ALIAS);
        byte[] binderGenerateChainBlob = BinderHookHandler.getGenerateKeyCertificateChainBlob(KEY_ALIAS);

        if (binderGenerateLeaf == null) {
            return false;
        }

        byte[] binderKeyEntryLeaf = BinderHookHandler.getKeyEntryLeafCertificate(KEY_ALIAS);
        byte[] referenceLeaf = binderKeyEntryLeaf != null
                ? binderKeyEntryLeaf
                : ctx.certChain.get(0).getEncoded();

        if (!Arrays.equals(binderGenerateLeaf, referenceLeaf)) {
            Log.e(
                    "PatchModeChecker",
                    "Patch mode detected: leaf certificate differs between generateKey and getKeyEntry");
            return true;
        } else if (binderKeyEntryLeaf != null) {
            byte[] binderKeyEntryChainBlob = BinderHookHandler.getKeyEntryCertificateChainBlob(KEY_ALIAS);
            List<byte[]> genFull = buildFullChainBytes(binderGenerateLeaf, binderGenerateChainBlob);
            List<byte[]> keyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
            if (!genFull.isEmpty() && !keyEntryFull.isEmpty() && !chainsEqualDer(genFull, keyEntryFull)) {
                Log.e("PatchModeChecker", "Patch mode detected: chain differs between generateKey and getKeyEntry");
                return true;
            }
        }

        return false;
    }

    @Override
    public String description() {
        return "Patch Mode Detected (%d)\nGenerateKey 与 GetKeyEntry 返回的证书链不一致";
    }
}
