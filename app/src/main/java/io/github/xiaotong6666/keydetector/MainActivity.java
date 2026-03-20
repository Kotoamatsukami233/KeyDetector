package io.github.xiaotong6666.keydetector;

import static io.github.xiaotong6666.keydetector.Util.getCheckerContext;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.R;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.textview.MaterialTextView;
import io.github.xiaotong6666.keydetector.checker.Checker;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends Activity {
    private static final String LOGCAT_TAG = "KeyDetectorLogView";
    private static final int MAX_LOG_LINES = 500;
    private static final long LOG_UI_UPDATE_DELAY_MS = 120L;
    private static final String AUTOFILL_HIDE_LOG = "requestHideFillUi(null): anchor = null";

    private final AtomicBoolean logReaderRunning = new AtomicBoolean(false);
    private final StringBuilder pendingLogLines = new StringBuilder();
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private ScrollView logScrollView;
    private MaterialTextView tvLog;
    private Thread logReaderThread;
    private java.lang.Process logcatProcess;
    private boolean stickLogToBottom = true;
    private boolean logUiUpdateScheduled = false;
    private boolean detectionRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        DynamicColors.applyToActivityIfAvailable(this);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        getWindow().getDecorView().setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);

        root.setBackgroundColor(MaterialColors.getColor(this, R.attr.colorSurface, Color.WHITE));

        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            var systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left + 32, systemBars.top + 32, systemBars.right + 32, systemBars.bottom + 32);
            return WindowInsetsCompat.CONSUMED;
        });

        MaterialTextView title = new MaterialTextView(this);
        title.setText("Key Detector");
        title.setTextAppearance(R.style.TextAppearance_Material3_HeadlineSmall);
        title.setTextColor(MaterialColors.getColor(this, R.attr.colorOnSurface, Color.BLACK));
        title.setGravity(Gravity.CENTER);
        title.setLayoutParams(new LinearLayout.LayoutParams(-1, -2));
        title.setPadding(0, 32, 0, 48);
        root.addView(title);

        MaterialButton btn = new MaterialButton(this);
        btn.setText("开始检测 (Key Attestation)");
        root.addView(btn);

        LinearLayout contentContainer = new LinearLayout(this);
        contentContainer.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams contentParams = new LinearLayout.LayoutParams(-1, 0);
        contentParams.topMargin = 32;
        contentParams.weight = 1f;
        contentContainer.setLayoutParams(contentParams);
        root.addView(contentContainer);

        MaterialTextView resultTitle = new MaterialTextView(this);
        resultTitle.setText("检测结果");
        resultTitle.setTextAppearance(R.style.TextAppearance_Material3_TitleMedium);
        resultTitle.setTextColor(MaterialColors.getColor(this, R.attr.colorOnSurface, Color.BLACK));
        contentContainer.addView(resultTitle);

        MaterialCardView resultCard = buildPanelCard();
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(-1, 0);
        scrollParams.topMargin = 16;
        scrollParams.weight = 1f;
        resultCard.setLayoutParams(scrollParams);

        ScrollView scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);
        scrollView.setBackgroundColor(Color.TRANSPARENT);
        scrollView.setPadding(16, 16, 16, 16);

        MaterialTextView tvResult = new MaterialTextView(this);
        tvResult.setText("点击按钮开始检测...");
        tvResult.setTextAppearance(R.style.TextAppearance_Material3_BodyMedium);
        tvResult.setTypeface(Typeface.MONOSPACE);

        scrollView.addView(tvResult);
        resultCard.addView(scrollView);
        contentContainer.addView(resultCard);

        MaterialTextView logTitle = new MaterialTextView(this);
        logTitle.setText("运行日志");
        logTitle.setTextAppearance(R.style.TextAppearance_Material3_TitleMedium);
        logTitle.setTextColor(MaterialColors.getColor(this, R.attr.colorOnSurface, Color.BLACK));
        LinearLayout.LayoutParams logTitleParams = new LinearLayout.LayoutParams(-1, -2);
        logTitleParams.topMargin = 24;
        logTitle.setLayoutParams(logTitleParams);
        contentContainer.addView(logTitle);

        MaterialCardView logCard = buildPanelCard();
        LinearLayout.LayoutParams logScrollParams = new LinearLayout.LayoutParams(-1, 0);
        logScrollParams.topMargin = 16;
        logScrollParams.weight = 1f;
        logCard.setLayoutParams(logScrollParams);

        logScrollView = new ScrollView(this);
        logScrollView.setFillViewport(true);
        logScrollView.setBackgroundColor(Color.TRANSPARENT);
        logScrollView.setPadding(16, 16, 16, 16);
        logScrollView
                .getViewTreeObserver()
                .addOnScrollChangedListener(() -> stickLogToBottom = isNearBottom(logScrollView));

        tvLog = new MaterialTextView(this);
        tvLog.setText("等待日志输出...");
        tvLog.setTextAppearance(R.style.TextAppearance_Material3_BodySmall);
        tvLog.setTypeface(Typeface.MONOSPACE);
        tvLog.setTextColor(MaterialColors.getColor(this, R.attr.colorOnSurfaceVariant, Color.DKGRAY));
        logScrollView.addView(tvLog);
        logCard.addView(logScrollView);
        contentContainer.addView(logCard);
        disableAutofillForViewTree(root);
        setContentView(root);
        startLogcatReader();

        btn.setOnClickListener(v -> {
            btn.setEnabled(false);
            detectionRunning = true;
            stickLogToBottom = true;
            tvResult.setText("正在生成密钥并验证证书链...\n请稍候...");
            // 优化：使用语义化颜色属性
            tvResult.setTextColor(MaterialColors.getColor(this, R.attr.colorOnSurfaceVariant, Color.GRAY));

            new Thread(() -> {
                        DetectorEngine detector = new DetectorEngine();
                        CheckerContext ctx = getCheckerContext(this);
                        int code = (ctx == null) ? 2 : detector.run(ctx);
                        String resultText = parseResult(code);

                        runOnUiThread(() -> {
                            tvResult.setText(resultText);
                            int targetAttr = (code == 1) ? android.R.attr.colorPrimary : android.R.attr.colorError;
                            tvResult.setTextColor(MaterialColors.getColor(this, targetAttr, Color.RED));
                            detectionRunning = false;
                            stickLogToBottom = false;
                            btn.setEnabled(true);
                        });
                    })
                    .start();
        });
    }

    @Override
    protected void onDestroy() {
        stopLogcatReader();
        mainHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    private String parseResult(int code) {
        StringBuilder sb = new StringBuilder("Status Code: " + code + "\n状态码: " + code + "\n\n");
        if (code == 1 || code == 0) {
            sb.append(parseSimpleStatus(code));
            return sb.toString();
        }
        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            if (entry.getValue() != null && (code & entry.getKey()) != 0) {
                sb.append(String.format(entry.getValue().description(), entry.getKey()))
                        .append("\n\n");
            }
        }
        return sb.toString();
    }

    private String parseSimpleStatus(int code) {
        return switch (code) {
            case 1 -> "Normal (1)";
            default -> "Something Wrong (" + code + ")";
        };
    }

    private void startLogcatReader() {
        if (logReaderRunning.getAndSet(true)) {
            return;
        }
        appendLogLine("Starting logcat stream for pid=" + Process.myPid());
        logReaderThread = new Thread(
                () -> {
                    try {
                        logcatProcess = new ProcessBuilder(
                                        "logcat", "-v", "threadtime", "--pid=" + Process.myPid(), "*:V")
                                .start();
                        try (BufferedReader reader =
                                new BufferedReader(new InputStreamReader(logcatProcess.getInputStream()))) {
                            String line;
                            while (logReaderRunning.get() && (line = reader.readLine()) != null) {
                                appendLogLine(line);
                            }
                        }
                    } catch (Exception e) {
                        appendLogLine("Failed to read logcat: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    } finally {
                        logReaderRunning.set(false);
                    }
                },
                "keydetector-logcat-reader");
        logReaderThread.start();
    }

    private void stopLogcatReader() {
        logReaderRunning.set(false);
        if (logcatProcess != null) {
            logcatProcess.destroy();
            logcatProcess = null;
        }
        if (logReaderThread != null) {
            logReaderThread.interrupt();
            logReaderThread = null;
        }
    }

    private void appendLogLine(String line) {
        if (shouldFilterLogLine(line)) {
            return;
        }
        synchronized (pendingLogLines) {
            if (pendingLogLines.length() > 0) {
                pendingLogLines.append('\n');
            }
            pendingLogLines.append(line);
            if (logUiUpdateScheduled) {
                return;
            }
            logUiUpdateScheduled = true;
        }
        mainHandler.postDelayed(this::flushPendingLogsToUi, LOG_UI_UPDATE_DELAY_MS);
    }

    private MaterialCardView buildPanelCard() {
        MaterialCardView card = new MaterialCardView(this);
        card.setRadius(36f);
        card.setCardElevation(0f);
        card.setUseCompatPadding(false);
        card.setPreventCornerOverlap(true);
        card.setCardBackgroundColor(MaterialColors.getColor(this, R.attr.colorSurfaceContainerLow, Color.LTGRAY));
        return card;
    }

    private static boolean isNearBottom(ScrollView scrollView) {
        if (scrollView == null || scrollView.getChildCount() == 0) {
            return true;
        }
        int thresholdPx = 48;
        int contentBottom = scrollView.getChildAt(0).getBottom();
        int viewportBottom = scrollView.getScrollY() + scrollView.getHeight();
        return contentBottom - viewportBottom <= thresholdPx;
    }

    private void flushPendingLogsToUi() {
        final String chunk;
        synchronized (pendingLogLines) {
            chunk = pendingLogLines.toString();
            pendingLogLines.setLength(0);
            logUiUpdateScheduled = false;
        }
        if (chunk.isEmpty()) {
            return;
        }
        boolean shouldStick = detectionRunning || (stickLogToBottom && isNearBottom(logScrollView));
        for (String line : chunk.split("\n")) {
            logLines.addLast(line);
            while (logLines.size() > MAX_LOG_LINES) {
                logLines.removeFirst();
            }
        }
        tvLog.setText(buildColoredLogText());
        if (shouldStick) {
            logScrollView.post(() -> logScrollView.fullScroll(ScrollView.FOCUS_DOWN));
        }
    }

    private CharSequence buildColoredLogText() {
        SpannableStringBuilder builder = new SpannableStringBuilder();
        boolean first = true;
        for (String line : logLines) {
            if (!first) {
                builder.append('\n');
            }
            first = false;
            int start = builder.length();
            builder.append(line);
            int color = colorForLogLine(line);
            builder.setSpan(new ForegroundColorSpan(color), start, builder.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        return builder;
    }

    private int colorForLogLine(String line) {
        char level = parseLogLevel(line);
        if (level == 0) {
            return MaterialColors.getColor(this, R.attr.colorOnSurfaceVariant, Color.DKGRAY);
        }
        return switch (level) {
            case 'V' -> MaterialColors.getColor(this, R.attr.colorOutline, Color.GRAY);
            case 'D' -> 0xff1565c0;
            case 'I' -> 0xff2e7d32;
            case 'W' -> 0xffb26a00;
            case 'E', 'F' -> 0xffb3261e;
            default -> MaterialColors.getColor(this, R.attr.colorOnSurfaceVariant, Color.DKGRAY);
        };
    }

    private static char parseLogLevel(String line) {
        if (line == null) {
            return 0;
        }
        String trimmed = line.trim();
        String[] parts = trimmed.split("\\s+", 6);
        if (parts.length >= 5 && parts[4].length() == 1) {
            char c = parts[4].charAt(0);
            if ("VDIWEF".indexOf(c) >= 0) {
                return c;
            }
        }
        int markerIndex = trimmed.indexOf(" V ");
        if (markerIndex < 0) markerIndex = trimmed.indexOf(" D ");
        if (markerIndex < 0) markerIndex = trimmed.indexOf(" I ");
        if (markerIndex < 0) markerIndex = trimmed.indexOf(" W ");
        if (markerIndex < 0) markerIndex = trimmed.indexOf(" E ");
        if (markerIndex < 0) markerIndex = trimmed.indexOf(" F ");
        return markerIndex >= 0 ? trimmed.charAt(markerIndex + 1) : 0;
    }

    private static boolean shouldFilterLogLine(String line) {
        return line != null && line.contains("AutofillManager") && line.contains(AUTOFILL_HIDE_LOG);
    }

    private static void disableAutofillForViewTree(View view) {
        view.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        if (view instanceof ViewGroup group) {
            for (int i = 0; i < group.getChildCount(); i++) {
                disableAutofillForViewTree(group.getChildAt(i));
            }
        }
    }
}
