package io.github.difhel.mtlshook;

import de.robv.android.xposed.XposedBridge;

final class Log {
    static final String TAG = "MtlsHook";

    static void i(String msg) {
        android.util.Log.i(TAG, msg);
        XposedBridge.log(TAG + ": " + msg);
    }

    static void w(String msg, Throwable t) {
        android.util.Log.w(TAG, msg, t);
        XposedBridge.log(TAG + ": " + msg + (t == null ? "" : ": " + t));
    }

    private Log() {}
}
