package io.github.difhel.mtlshook;

import android.app.Activity;
import android.net.Uri;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import java.lang.reflect.Method;
import java.security.Principal;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * Apps with their own TLS stack (Chrome's BoringSSL) call KeyChain.choosePrivateKeyAlias,
 * which shows the system picker. For requests from an allowed host that name our CA, answer
 * with our alias instead;
 * the app then loads it with KeyChain.getPrivateKey/getCertificateChain as usual.
 * The (host, port) overload delegates to this Uri overload.
 */
final class KeyChainChooserHook {
    static void install() {
        try {
            Method m = KeyChain.class.getDeclaredMethod("choosePrivateKeyAlias", Activity.class, KeyChainAliasCallback.class,
                    String[].class, Principal[].class, Uri.class, String.class);
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String[] keyTypes = (String[]) param.args[2];
                    Principal[] issuers = (Principal[]) param.args[3];
                    Uri uri = (Uri) param.args[4];
                    String host = uri == null ? null : InjectingKeyManager.hostFromAuthority(uri.getAuthority());
                    if (!InjectingKeyManager.shouldOffer(host, keyTypes, issuers, "KeyChain chooser")) return;
                    final KeyChainAliasCallback callback = (KeyChainAliasCallback) param.args[1];
                    param.setResult(null);
                    // KeyChain itself answers on a binder thread; never on the caller's (UI) thread.
                    new Thread(() -> callback.alias(Config.KEYCHAIN_ALIAS), "mtlshook-alias").start();
                }
            });
            Log.i("hooked KeyChain.choosePrivateKeyAlias");
        } catch (Throwable t) {
            Log.w("cannot hook KeyChain.choosePrivateKeyAlias", t);
        }
    }

    private KeyChainChooserHook() {}
}
