package io.github.difhel.mtlshook;

import android.content.Context;
import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * Runs in com.android.keychain. KeyChainService only hands an alias (keystore2 grant,
 * certificate) to apps the user picked it for. Report a grant for our alias to whitelisted
 * apps, so they never need the picker. Nothing is written to the grants database: disabling
 * the module removes the access.
 */
final class KeyChainGrantHook {
    static void install(ClassLoader loader) {
        // Binder-facing check used by requestPrivateKey/getCertificate.
        hook(loader, "com.android.keychain.KeyChainService$1", String.class, int.class, 0, 1);
        // The database lookup beneath it, in case ART inlined the private method above.
        hook(loader, "com.android.keychain.internal.GrantsDatabase", int.class, String.class, 1, 0);
    }

    private static void hook(ClassLoader loader, String className, Class<?> p0, Class<?> p1, int aliasIdx, int uidIdx) {
        try {
            Method m = Class.forName(className, false, loader).getDeclaredMethod("hasGrant", p0, p1);
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.hasThrowable() || Boolean.TRUE.equals(param.getResult())) return;
                    if (!Config.KEYCHAIN_ALIAS.equals(param.args[aliasIdx])) return;
                    int uid = (Integer) param.args[uidIdx];
                    Context ctx = KeyMaterial.context();
                    String[] pkgs = ctx == null ? null : ctx.getPackageManager().getPackagesForUid(uid);
                    if (pkgs == null) return;
                    for (String pkg : pkgs) {
                        if (Config.isWhitelisted(pkg)) {
                            Log.i("grant " + Config.KEYCHAIN_ALIAS + " to uid " + uid + " (" + pkg + ") via " + className);
                            param.setResult(true);
                            return;
                        }
                    }
                }
            });
            Log.i("hooked " + className + ".hasGrant");
        } catch (Throwable t) {
            Log.w("cannot hook " + className + ".hasGrant", t);
        }
    }

    private KeyChainGrantHook() {}
}
