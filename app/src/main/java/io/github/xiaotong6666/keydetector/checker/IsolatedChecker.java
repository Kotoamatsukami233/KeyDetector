package io.github.xiaotong6666.keydetector.checker;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.service.IsolationService;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class IsolatedChecker extends Checker {
    private static final String TAG = "IsolatedChecker";

    @Override
    public String name() {
        return "Isolated Process Check";
    }

    @Override
    public String description() {
        return "Isolation Environment Anomaly (%d)\nIsolated Process detected suspicious properties (e.g. dummy vbmeta)";
    }

    @Override
    public boolean check(CheckerContext ctx) {
        final BlockingQueue<Integer> resultQueue = new LinkedBlockingQueue<>();

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    service.transact(1, data, reply, 0);
                    reply.readException();
                    int res = reply.readInt();
                    resultQueue.offer(res);
                } catch (Exception e) {
                    Log.e(TAG, "Transact failed", e);
                    resultQueue.offer(-1);
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                // Ignore
            }
        };

        try {
            Intent intent = new Intent(ctx.appContext, IsolationService.class);
            boolean bound = ctx.appContext.bindService(intent, conn, Context.BIND_AUTO_CREATE);
            if (!bound) {
                Log.e(TAG, "Failed to bind IsolationService");
                return false; // Fail open or closed? Let's say false = no error detected (safe)
            }

            try {
                Integer res = resultQueue.poll(5, TimeUnit.SECONDS);
                if (res == null) {
                    Log.e(TAG, "Timeout waiting for IsolationService");
                    return false;
                }
                if (res == -1) {
                    return false; // IPC error
                }
                if (res != 0) {
                    Log.e(TAG, "IsolationService reported anomaly: " + res);
                    return true;
                }
                return false;

            } catch (InterruptedException e) {
                Log.e(TAG, "Interrupted", e);
                return false;
            } finally {
                ctx.appContext.unbindService(conn);
            }

        } catch (Exception e) {
            Log.e(TAG, "Check failed", e);
            return false;
        }
    }
}
