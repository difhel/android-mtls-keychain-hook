package io.github.difhel.mtlshook;

import android.content.Context;
import android.security.KeyChain;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** Loads the KeyChain key pair in the app process (KeyChain access comes from KeyChainGrantHook). */
final class KeyMaterial {
    private static X509Certificate[] chain;
    private static PrivateKey key;

    static synchronized X509Certificate[] chain() {
        if (chain == null) {
            try {
                chain = KeyChain.getCertificateChain(context(), Config.KEYCHAIN_ALIAS);
                Log.i("KeyChain chain for " + Config.KEYCHAIN_ALIAS + ": "
                        + (chain == null ? "null (not installed or no grant)" : chain.length + " cert(s), leaf " + chain[0].getSubjectX500Principal()));
            } catch (Throwable t) {
                Log.w("KeyChain.getCertificateChain failed", t);
            }
        }
        return chain;
    }

    static synchronized PrivateKey privateKey() {
        if (key == null) {
            try {
                key = KeyChain.getPrivateKey(context(), Config.KEYCHAIN_ALIAS);
                Log.i("KeyChain key for " + Config.KEYCHAIN_ALIAS + ": " + (key == null ? "null (not installed or no grant)" : key.getAlgorithm()));
            } catch (Throwable t) {
                Log.w("KeyChain.getPrivateKey failed", t);
            }
        }
        return key;
    }

    static Context context() throws ReflectiveOperationException {
        return (Context) Class.forName("android.app.ActivityThread").getMethod("currentApplication").invoke(null);
    }

    private KeyMaterial() {}
}
