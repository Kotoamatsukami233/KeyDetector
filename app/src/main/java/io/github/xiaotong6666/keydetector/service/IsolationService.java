package io.github.xiaotong6666.keydetector.service;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import java.lang.reflect.Method;

public class IsolationService extends Service {
    private static final String TAG = "IsolationService";
    // Mirror standard error codes or simplified ones
    // 0 = OK, 1 = Error

    private final Binder mBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code == 1) { // Check Command
                int result = checkEnvironment();
                reply.writeNoException();
                reply.writeInt(result);
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private int checkEnvironment() {
        int result = 0;

        // 1. Check ro.boot.vbmeta.digest
        String vbmetaDigest = getSystemProperty("ro.boot.vbmeta.digest");
        if (vbmetaDigest != null && vbmetaDigest.matches("0+")) {
            Log.e(TAG, "Isolated: Dummy vbmeta digest detected");
            result |= 1;
        }

        // 2. We could check other props that might be different in isolated process
        // e.g. Magisk specific props might be visible or hidden differently

        return result;
    }

    private String getSystemProperty(String key) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method m = c.getDeclaredMethod("get", String.class);
            return (String) m.invoke(null, key);
        } catch (Exception e) {
            return null;
        }
    }
}
