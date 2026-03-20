package io.github.xiaotong6666.keydetector.checker;

import java.security.KeyStore;

final class KeyMetadataProbeHelper {
    private KeyMetadataProbeHelper() {}

    static ProbeData load(KeyStore keyStore, String alias) throws Exception {
        KeystoreProbeHelper.cleanupAlias(keyStore, alias);
        KeystoreProbeHelper.generateEcKey(KeystoreProbeHelper.newEcSigningKeyBuilder(
                alias, android.security.keystore.KeyProperties.PURPOSE_SIGN));

        Object service = Reflection.getIKeystoreService();
        Object keyEntryResponse = Reflection.getKeyEntry(service, Reflection.createKeyDescriptor(alias));

        return new ProbeData(
                keyEntryResponse,
                Reflection.getReturnedKeyDescriptor(keyEntryResponse),
                Reflection.getMetadata(keyEntryResponse));
    }

    static final class ProbeData {
        final Object keyEntryResponse;
        final Object returnedDescriptor;
        final Object metadata;

        ProbeData(Object keyEntryResponse, Object returnedDescriptor, Object metadata) {
            this.keyEntryResponse = keyEntryResponse;
            this.returnedDescriptor = returnedDescriptor;
            this.metadata = metadata;
        }
    }
}
