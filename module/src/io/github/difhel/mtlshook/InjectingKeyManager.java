package io.github.difhel.mtlshook;

import java.lang.reflect.Method;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * Delegates to the app's key manager, and when that declines a client certificate request
 * from an allowed host that names our CA, offers the KeyChain key pair under a private
 * sentinel alias.
 * Stateless apart from the delegate: a fresh wrapper per getX509KeyManager() call is fine.
 */
final class InjectingKeyManager extends X509ExtendedKeyManager {
    static final String SENTINEL = "io.github.difhel.mtlshook/" + Config.KEYCHAIN_ALIAS;
    private static final InjectingKeyManager NO_DELEGATE = new InjectingKeyManager(null);
    private static final X500Principal CA = new X500Principal(Config.CA_SUBJECT);

    private final X509KeyManager delegate;

    private InjectingKeyManager(X509KeyManager delegate) {
        this.delegate = delegate;
    }

    static X509KeyManager wrap(X509KeyManager delegate) {
        return delegate == null ? NO_DELEGATE : new InjectingKeyManager(delegate);
    }

    /**
     * True when a request should get our key: the host is on the allow-list AND the server's
     * CertificateRequest names our CA (a CA name alone is public and could be copied by anyone)
     * AND the key type fits. An unknown host is never offered the key.
     */
    static boolean shouldOffer(String host, String[] keyTypes, Principal[] issuers, String where) {
        if (!Config.isHostAllowed(host)) {
            Log.i(where + ": client cert requested by " + host + " (not on the host allow-list) -> decline");
            return false;
        }
        boolean typeOk = keyTypes == null || keyTypes.length == 0 || Arrays.asList(keyTypes).contains(Config.KEY_TYPE);
        boolean issuerOk;
        if (issuers == null || issuers.length == 0) {
            issuerOk = Config.OFFER_ON_EMPTY_ISSUERS;
        } else {
            issuerOk = false;
            for (Principal p : issuers) {
                if (matchesCa(p)) {
                    issuerOk = true;
                    break;
                }
            }
        }
        Log.i(where + ": client cert requested by " + host + ", keyTypes=" + Arrays.toString(keyTypes)
                + " issuers=" + Arrays.toString(issuers) + " -> " + (typeOk && issuerOk ? "offer " + Config.KEYCHAIN_ALIAS : "decline"));
        return typeOk && issuerOk;
    }

    /** Peer host of a client socket during the handshake (SNI name), without reverse DNS. */
    static String peerHost(Socket socket) {
        if (socket instanceof SSLSocket) {
            try {
                SSLSession s = ((SSLSocket) socket).getHandshakeSession();
                if (s != null && s.getPeerHost() != null) return s.getPeerHost();
            } catch (Throwable ignored) {
                // fall through to Conscrypt's own accessors
            }
        }
        for (Class<?> c = socket == null ? null : socket.getClass(); c != null; c = c.getSuperclass()) {
            for (String name : new String[] {"getHostname", "getHostnameOrIP"}) {
                try {
                    Method m = c.getDeclaredMethod(name);
                    m.setAccessible(true);
                    Object host = m.invoke(socket);
                    if (host instanceof String && !((String) host).isEmpty()) return (String) host;
                } catch (Throwable ignored) {
                    // not declared on this class
                }
            }
        }
        return null;
    }

    /** Host of a KeyChain chooser Uri; its authority is "host:port" with the colon percent-encoded. */
    static String hostFromAuthority(String authority) {
        if (authority == null) return null;
        String a = authority;
        int at = a.lastIndexOf('@');
        if (at >= 0) a = a.substring(at + 1);
        if (a.startsWith("[")) {
            int end = a.indexOf(']');
            return end > 0 ? a.substring(1, end) : null;
        }
        int colon = a.lastIndexOf(':');
        return colon >= 0 ? a.substring(0, colon) : a;
    }

    private static boolean matchesCa(Principal p) {
        try {
            X500Principal x = p instanceof X500Principal ? (X500Principal) p : new X500Principal(p.getName());
            return CA.equals(x);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        if (delegate != null) {
            String alias = delegate.chooseClientAlias(keyTypes, issuers, socket);
            if (alias != null) return alias;
        }
        return shouldOffer(peerHost(socket), keyTypes, issuers, "socket") ? SENTINEL : null;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        if (delegate != null) {
            String alias = delegate instanceof X509ExtendedKeyManager
                    ? ((X509ExtendedKeyManager) delegate).chooseEngineClientAlias(keyTypes, issuers, engine)
                    : delegate.chooseClientAlias(keyTypes, issuers, null);
            if (alias != null) return alias;
        }
        return shouldOffer(engine == null ? null : engine.getPeerHost(), keyTypes, issuers, "engine") ? SENTINEL : null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (SENTINEL.equals(alias)) return KeyMaterial.chain();
        return delegate == null ? null : delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (SENTINEL.equals(alias)) return KeyMaterial.privateKey();
        return delegate == null ? null : delegate.getPrivateKey(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return delegate == null ? null : delegate.getClientAliases(keyType, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate == null ? null : delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate == null ? null : delegate.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        if (delegate instanceof X509ExtendedKeyManager) {
            return ((X509ExtendedKeyManager) delegate).chooseEngineServerAlias(keyType, issuers, engine);
        }
        return delegate == null ? null : delegate.chooseServerAlias(keyType, issuers, null);
    }
}
