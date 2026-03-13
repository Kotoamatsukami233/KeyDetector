package com.xiaotong.keydetector.handler;

import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Intercepts Keystore Binder calls by replacing the IKeystoreService in
 * ServiceManager.sCache.
 * This allows us to capture the "true" certificate chain returned by the system
 * service
 * before any Java-level hooks might tamper with it.
 */
public class KeystoreInterceptor {
    private static final String TAG = "KeystoreInterceptor";
    private static final Map<String, byte[]> capturedChains = new ConcurrentHashMap<>();
    private static boolean isInstalled = false;

    public static synchronized void install() {
        if (isInstalled) return;
        try {
            if (Build.VERSION.SDK_INT >= 31) {
                installKeystore2();
            } else {
                installLegacyKeystore();
            }
            isInstalled = true;
            Log.i(TAG, "KeystoreInterceptor installed successfully");
        } catch (Throwable e) {
            Log.e(TAG, "Failed to install KeystoreInterceptor", e);
        }
    }

    public static byte[] getCapturedChain(String alias) {
        return capturedChains.get(alias);
    }

    public static void clear() {
        capturedChains.clear();
    }

    private static void installKeystore2() throws Exception {
        // Target: android.system.keystore2.IKeystoreService
        final String SERVICE_NAME = "android.system.keystore2.IKeystoreService/default";
        final String INTERFACE_NAME = "android.system.keystore2.IKeystoreService";
        final String STUB_PROXY_NAME = "android.system.keystore2.IKeystoreService$Stub$Proxy";

        replaceService(SERVICE_NAME, INTERFACE_NAME, STUB_PROXY_NAME);
    }

    private static void installLegacyKeystore() throws Exception {
        // Target: android.security.keystore.IKeystoreService (or
        // android.security.IKeystoreService on older)
        final String SERVICE_NAME = "android.security.keystore";
        String interfaceName = "android.security.keystore.IKeystoreService";
        try {
            Class.forName(interfaceName);
        } catch (ClassNotFoundException e) {
            interfaceName = "android.security.IKeystoreService";
        }
        final String STUB_PROXY_NAME = interfaceName + "$Stub$Proxy";

        replaceService(SERVICE_NAME, interfaceName, STUB_PROXY_NAME);
    }

    private static void replaceService(String serviceName, String interfaceName, String stubProxyName)
            throws Exception {
        // 1. Get sCache from ServiceManager
        Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
        Field sCacheField = serviceManagerClass.getDeclaredField("sCache");
        sCacheField.setAccessible(true);
        Map<String, IBinder> sCache = (Map<String, IBinder>) sCacheField.get(null);

        // 2. Remove existing cached service to force a fresh fetch (or just get it)
        // We actually want to wrap the *real* service.
        Method getServiceMethod = serviceManagerClass.getMethod("getService", String.class);
        IBinder realService = (IBinder) getServiceMethod.invoke(null, serviceName);

        if (realService == null) {
            Log.w(TAG, "Real service " + serviceName + " not found");
            return;
        }

        // 3. Create the Proxy
        Class<?> interfaceClass = Class.forName(interfaceName);
        Class<?> stubProxyClass = Class.forName(stubProxyName);
        Constructor<?> constructor = stubProxyClass.getDeclaredConstructor(IBinder.class);
        constructor.setAccessible(true);

        // The object that implements the interface and delegates to the real Binder
        Object realInterface = constructor.newInstance(realService);

        InvocationHandler handler = (proxy, method, args) -> {
            try {
                Object result = method.invoke(realInterface, args);

                // Intercept logic
                if ("generateKey".equals(method.getName()) || "getKeyEntry".equals(method.getName())) {
                    try {
                        inspectResult(result, args, serviceName);
                    } catch (Throwable t) {
                        Log.e(TAG, "Error inspecting result", t);
                    }
                }

                return result;
            } catch (Throwable t) {
                if (t instanceof java.lang.reflect.InvocationTargetException) {
                    throw t.getCause();
                }
                throw t;
            }
        };

        Object proxyService =
                Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[] {interfaceClass}, handler);

        // 4. We also need to hook the Binder itself if the system queries it?
        // Actually, ServiceManager.getService returns an IBinder.
        // The application code calls
        // IKeystoreService.Stub.asInterface(ServiceManager.getService(...))
        // So we need to put an IBinder in sCache that, when asInterface is called,
        // returns OUR proxy.
        // Wait, sCache stores IBinder.
        // When Stub.asInterface(binder) is called:
        // if (binder instanceof IInterface) return (IInterface) binder;
        // So if we put our Proxy (which implements IInterface) technically it might
        // work but
        // sCache expects IBinder. Proxy implements the Service Interface, not
        // necessarily IBinder.

        // The obfuscated code creates a Proxy for the Service Interface.
        // AND it puts a Proxy for IBinder into sCache?
        // Let's re-read the obfuscated code logic in C0154v1/KeyAttestation.

        // Obfuscated code breakdown:
        // map.remove(serviceName);
        // IBinder service = ServiceManager.getService(serviceName);
        // ... creates proxy for Interface ...
        // map.put(serviceName, Proxy.newProxyInstance(..., new Class[]{IBinder.class},
        // ...));

        // Ah, it replaces the IBinder in sCache with a Proxy that implements IBinder.
        // When queryLocalInterface is called on that IBinder proxy, it returns the
        // Interface Proxy.

        // Let's implement that specific structure.

        InvocationHandler binderHandler = (proxy, method, args) -> {
            if ("queryLocalInterface".equals(method.getName())) {
                return proxyService; // Return our hooked Interface
            }
            // For other methods (transact, linkToDeath, etc.), delegate to real Binder
            return method.invoke(realService, args);
        };

        Object binderProxy =
                Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[] {IBinder.class}, binderHandler);

        // 5. Inject into sCache
        sCache.put(serviceName, (IBinder) binderProxy);
    }

    private static void inspectResult(Object result, Object[] args, String serviceName) {
        if (result == null) return;

        // Keystore 2.0 (Android 12+) returns KeyMetadata or KeyEntryResponse
        // Reflection to avoid compile-time dependencies issues or class errors on old
        // API
        try {
            Class<?> resultClass = result.getClass();
            byte[] certBytes = null;
            byte[] chainBytes = null;
            String alias = null;

            // Attempt to get Alias from args.
            // generateKey(KeyDescriptor descriptor, ...) -> descriptor.alias
            // getKeyEntry(KeyDescriptor descriptor) -> descriptor.alias
            // Legacy: generateKey(String alias, ...)

            if (args != null && args.length > 0) {
                Object arg0 = args[0];
                if (arg0 instanceof String) {
                    alias = (String) arg0;
                } else if (arg0.getClass().getName().equals("android.system.keystore2.KeyDescriptor")) {
                    Field aliasField = arg0.getClass().getField("alias");
                    alias = (String) aliasField.get(arg0);
                }
            }

            if (alias == null) return;

            // Extract Certificate Chain
            // Keystore2 uses 'metadata' field which contains 'certificate' and
            // 'certificateChain'.
            // KeyMetadata (generateKey return) has 'certificate' and 'certificateChain'
            // directly?
            // Actually KeyMetadata has 'certificate' and 'certificateChain'.
            // KeyEntryResponse has 'metadata' which is KeyMetadata.

            Object metadata = result;
            if (resultClass.getName().equals("android.system.keystore2.KeyEntryResponse")) {
                Field metadataField = resultClass.getField("metadata");
                metadata = metadataField.get(result);
                if (metadata == null) return;
                resultClass = metadata.getClass();
            }

            if (resultClass.getName().equals("android.system.keystore2.KeyMetadata")) {
                Field certField = resultClass.getField("certificate");
                Field chainField = resultClass.getField("certificateChain");
                certBytes = (byte[]) certField.get(metadata);
                chainBytes = (byte[]) chainField.get(metadata);

                // If chain exists, use it. In Keystore2, chain usually contains the rest.
                // We want the leaf + chain.
                processCapturedChain(alias, certBytes, chainBytes);
            }

            // Should also support Legacy keystore if possible, but Android 12+ is the main
            // target for this bypass.
            // On Legacy, generateKey returns void or int (error code). It doesn't return
            // the chain.
            // The chain is retrieved via get().
            // So for Legacy, we might only be able to intercept 'get'.

        } catch (Exception e) {
            Log.w(TAG, "Inspection failed: " + e.getMessage());
        }
    }

    private static void processCapturedChain(String alias, byte[] leaf, byte[] chain) {
        // Store the leaf (or full encoded chain if we reconstruct it)
        // For consistency check, we usually compare the Leaf certificate.
        if (leaf != null) {
            Log.d(TAG, "Captured certificate for " + alias);
            capturedChains.put(alias, leaf);
        }
    }
}
