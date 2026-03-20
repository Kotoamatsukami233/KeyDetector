package com.xiaotong.keydetector.checker;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

final class ListEntriesProbeHelper {
    private ListEntriesProbeHelper() {}

    static void prepareSigningKey(KeyStore keyStore, String alias) throws Exception {
        KeystoreProbeHelper.cleanupAlias(keyStore, alias);
        KeystoreProbeHelper.generateEcKey(KeystoreProbeHelper.newEcSigningKeyBuilder(
                alias, android.security.keystore.KeyProperties.PURPOSE_SIGN));
    }

    static AliasPair newAliasPair() {
        String aliasPrefix = "zzzz_" + UUID.randomUUID().toString().replace("-", "");
        return new AliasPair(aliasPrefix + "_0", aliasPrefix + "_1");
    }

    static List<String> collectJavaAliases(KeyStore keyStore) throws Exception {
        List<String> aliases = new ArrayList<>();
        Enumeration<String> aliasesEnum = keyStore.aliases();
        while (aliasesEnum.hasMoreElements()) {
            aliases.add(aliasesEnum.nextElement());
        }
        return aliases;
    }

    static List<String> extractAliasesFromDescriptors(Object result) throws Exception {
        List<String> aliases = new ArrayList<>();
        for (Object descriptor : Reflection.toObjectArray(result)) {
            if (descriptor == null) {
                continue;
            }
            String alias = Reflection.getStringField(descriptor, "alias");
            if (alias != null) {
                aliases.add(alias);
            }
        }
        return aliases;
    }

    static final class AliasPair {
        final String first;
        final String second;

        AliasPair(String first, String second) {
            this.first = first;
            this.second = second;
        }
    }
}
