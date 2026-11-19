package io.github.difhel.mtlsprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 * Plain HttpsURLConnection client with no client-certificate code at all: whatever
 * certificate the server sees comes from the hook. Fetches on launch and on every resume.
 *   adb shell am start -S -n io.github.difhel.mtlsprobe/.MainActivity [--es url https://...]
 */
public final class MainActivity extends Activity {
    private static final String TAG = "MtlsProbe";
    private static final String DEFAULT_URL = "https://mtls.example.com/";
    private TextView view;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        view = new TextView(this);
        view.setPadding(40, 120, 40, 40);
        view.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(view);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        String url = getIntent().getStringExtra("url");
        final String target = url == null ? DEFAULT_URL : url;
        view.setText("GET " + target + " ...");
        new Thread(() -> {
            String result = fetch(target);
            Log.i(TAG, result.replace("\n", " | "));
            runOnUiThread(() -> view.setText("GET " + target + "\n\n" + result));
        }, "probe").start();
    }

    private static String fetch(String target) {
        HttpsURLConnection c = null;
        try {
            c = (HttpsURLConnection) new URL(target).openConnection();
            c.setConnectTimeout(10000);
            c.setReadTimeout(10000);
            int code = c.getResponseCode();
            InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            for (int n; in != null && (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
            return "HTTP " + code + "\n" + out.toString("UTF-8");
        } catch (Exception e) {
            return "ERROR " + e;
        } finally {
            if (c != null) c.disconnect();
        }
    }
}
