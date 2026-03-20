package io.github.xiaotong6666.keydetector.checker;

import android.util.Log;
import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.handler.BinderHookHandler;

public final class BinderHookChecker extends Checker {
    private static final String TAG = "BinderHookChecker";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        boolean hookSuccess = BinderHookHandler.isHookSuccess();
        if (!hookSuccess) {
            Log.e(TAG, "ANOMALY: Binder hook bootstrap did not complete successfully.");
        } else {
            Log.d(TAG, "Binder hook bootstrap confirmed.");
        }
        return !hookSuccess;
    }

    @Override
    public String description() {
        return "Hook Failed (%d)\n尝试 Hook ServiceManager 失败";
    }
}
