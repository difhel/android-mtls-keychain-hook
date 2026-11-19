package io.github.difhel.mtlshook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** Module entry (assets/xposed_init). */
public final class Entry implements IXposedHookLoadPackage {
    private static boolean appHooksInstalled;
    private static boolean keyChainHooksInstalled;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if ("com.android.keychain".equals(lp.packageName)) {
            synchronized (Entry.class) {
                if (keyChainHooksInstalled) return;
                keyChainHooksInstalled = true;
            }
            Log.i("load " + lp.packageName + " in " + lp.processName + ": installing KeyChain grant hooks");
            KeyChainGrantHook.install(lp.classLoader);
            return;
        }
        if (!Config.isWhitelisted(lp.packageName)) {
            return;
        }
        synchronized (Entry.class) {
            if (appHooksInstalled) {
                // Bundled Conscrypt lives in the app class loader: still check it.
                ConscryptHook.install(lp.classLoader, "org.conscrypt.SSLParametersImpl");
                return;
            }
            appHooksInstalled = true;
        }
        Log.i("load " + lp.packageName + " in " + lp.processName + ": installing TLS client cert hooks");
        // Platform Conscrypt: HttpsURLConnection, OkHttp on Android, SSLSocket/SSLEngine users.
        ConscryptHook.install(null, "com.android.org.conscrypt.SSLParametersImpl");
        // Apps that ship their own Conscrypt (org.conscrypt:conscrypt-android).
        ConscryptHook.install(lp.classLoader, "org.conscrypt.SSLParametersImpl");
        // Chrome and anything else that asks the user to pick a KeyChain alias.
        KeyChainChooserHook.install();
    }
}
