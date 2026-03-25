package io.github.xiaotong6666.keydetector.checker;

import android.content.Context;
import android.util.Log;
import com.tencent.soter.core.SoterCore;

public final class SoterSupportChecker {
    private static final String TAG = "KeyDetectorSoter";

    private SoterSupportChecker() {}

    public static Result probe(Context context, LogSink logSink) {
        appendLog(logSink, "Checking SOTER support (native)...");

        SoterCore.tryToInitSoterBeforeTreble();
        SoterCore.tryToInitSoterTreble(context);
        SoterCore.setUp();

        boolean support = SoterCore.isNativeSupportSoter();
        int coreType = SoterCore.getSoterCoreType();
        boolean trebleConnected = SoterCore.isTrebleServiceConnected();

        appendLog(
                logSink,
                "SOTER support=" + support + ", coreType=" + coreType + ", trebleConnected=" + trebleConnected);
        if (!support) {
            appendLog(logSink, "Device does not support SOTER key");
        }
        return new Result(support, coreType, trebleConnected);
    }

    private static void appendLog(LogSink logSink, String message) {
        Log.i(TAG, message);
        if (logSink != null) {
            logSink.append("[SOTER] " + message);
        }
    }

    public interface LogSink {
        void append(String message);
    }

    public static final class Result {
        public final boolean supported;
        public final int coreType;
        public final boolean trebleConnected;

        public Result(boolean supported, int coreType, boolean trebleConnected) {
            this.supported = supported;
            this.coreType = coreType;
            this.trebleConnected = trebleConnected;
        }
    }
}
