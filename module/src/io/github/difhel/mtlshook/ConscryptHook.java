package io.github.difhel.mtlshook;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.X509KeyManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * Conscrypt asks SSLParametersImpl.getX509KeyManager() for the key manager both when the
 * server sends a CertificateRequest (NativeSsl.chooseClientCertificate) and when it loads the
 * chosen alias (NativeSsl.setCertificate). Wrapping its result in client mode lets the
 * KeyChain key answer requests that the app's own key manager (usually none) declines.
 */
final class ConscryptHook {
    private static final Set<Class<?>> hooked = new HashSet<>();

    static void install(ClassLoader loader, String className) {
        final Class<?> params;
        try {
            params = Class.forName(className, false, loader);
        } catch (ClassNotFoundException e) {
            return;
        }
        synchronized (hooked) {
            if (!hooked.add(params)) return;
        }
        try {
            final Method getter = params.getDeclaredMethod("getX509KeyManager");
            final Method clientMode = params.getDeclaredMethod("getUseClientMode");
            clientMode.setAccessible(true);
            XposedBridge.hookMethod(getter, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.hasThrowable()) return;
                    Object result = param.getResult();
                    if (result instanceof InjectingKeyManager) return;
                    if (!(Boolean) clientMode.invoke(param.thisObject)) return;
                    param.setResult(InjectingKeyManager.wrap((X509KeyManager) result));
                }
            });
            Log.i("hooked " + className + ".getX509KeyManager (loader " + params.getClassLoader() + ")");
        } catch (Throwable t) {
            Log.w("cannot hook " + className, t);
        }
    }

    private ConscryptHook() {}
}
