# android-mtls-keychain-hook

Companion code for the article *[I Hated Running a VPN on Android, So I Built My Own Zero Trust
Infra Instead](https://difhel.dev/en/blog/zero-trust-beyond-vpn)*: make **unmodified** Android apps and Chrome present a client certificate (mTLS)
from the system KeyChain, without a VPN.

- `module/`: an Xposed module (legacy API; runs on LSPosed / Vector).
- `probe/`: a tiny test app that does a plain `HttpsURLConnection` GET with **no** client
  certificate code of its own.
- `nginx/mtls.example.com.conf`: the server side.
- `gen-pki.sh`: an example CA and device certificate. `build.sh`: builds both APKs without Gradle.

## How it works

The key is a normal KeyChain entry ("VPN & app user certificate"), so it lives in the TEE and
never leaves the hardware. The module only decides *who* may use it and *when*:

1. **Platform TLS** (`HttpsURLConnection`, OkHttp, Retrofit, anything on Conscrypt): it wraps
   `SSLParametersImpl.getX509KeyManager()` in client mode. On a CertificateRequest the app's own
   key manager is asked first; if it declines, the wrapper answers with the KeyChain key.
2. **Chrome** (own BoringSSL, asks the system picker): `KeyChain.choosePrivateKeyAlias` is
   answered with the alias instead of showing the dialog.
3. **KeyChain service** (`com.android.keychain`): whitelisted packages are reported as having a
   grant for the alias, so they get the key without the per-app consent dialog. Nothing is written
   to the grants database; disable the module and the access is gone. A non-whitelisted app that
   calls `KeyChain.getPrivateKey()` with the right alias still gets `null`.

The key is offered only when **all** of these hold:

- the app is in `packages`,
- the server's host is in `hosts`,
- the server's CertificateRequest names the CA from `ca.cert` (so the CA name alone, which is
  public, is not enough),
- the requested key types include `key.type`.

## Requirements

- A rooted phone with Zygisk and LSPosed or [Vector](https://github.com/JingMatrix/Vector).
  Tested on a Pixel 6, Android 16, KernelSU Next + Zygisk Next + Vector 2.2.
- To build: Android SDK (build-tools, `platforms;android-36`), JDK 17+, `openssl`, `python3`, `zip`.

## Quick start

```bash
# 1. PKI: pki/ca.crt for nginx, pki/phone.p12 for the phone
./gen-pki.sh phone

# 2. Server: nginx/mtls.example.com.conf with ssl_client_certificate = pki/ca.crt.
#    Publish the host directly (DNS-only): a CDN that terminates TLS drops the client cert.

# 3. Configure and build (edit module/module.properties: hosts, packages, keychain.alias)
./build.sh
adb install -r build/mtlshook.apk
adb install -r build/mtlsprobe.apk
```

4. **Install the certificate**: copy `pki/phone.p12` to the phone and open it (Settings →
   Security → Encryption & credentials → Install a certificate → VPN & app user certificate).
   Keep the suggested name `mtls-phone`, it must match `keychain.alias`. Delete the file afterwards.
5. **Enable the module** and its scope: the apps from `packages` plus `com.android.keychain`.
   With Vector's CLI (build.sh prints the exact command):
   ```bash
   adb shell su -c '/data/adb/lspd/cli modules enable io.github.difhel.mtlshook'
   adb shell su -c '/data/adb/lspd/cli scope set io.github.difhel.mtlshook com.android.chrome/0 io.github.difhel.mtlsprobe/0 com.android.keychain/0'
   ```
6. **KernelSU only**: if modules are unmounted by default and Zygisk Next enforces its denylist,
   Vector is silently not injected. In KernelSU → Superuser, give every scoped app *and* Key Chain
   a custom profile with **Umount modules** off.
7. Restart the apps (`adb shell am force-stop ...`) and the KeyChain service
   (`adb shell su -c 'pkill -f com.android.keychain'`).

Check it:

```bash
adb shell am start -S -n io.github.difhel.mtlsprobe/.MainActivity --es url https://mtls.example.com/
adb logcat -s MtlsHook MtlsProbe
```

Expected: `... client cert requested by mtls.example.com ... -> offer mtls-phone`, a grant line
from the KeyChain process, and an HTTP 200 from your backend. With the module disabled the same
request gets nginx's 400.

## Configuration (`module/module.properties`)

| Key | Meaning |
|---|---|
| `keychain.alias` | Alias of the key pair in the KeyChain |
| `packages` | Apps that get the hooks and KeyChain access (also add them to the scope) |
| `hosts` | Hosts that may receive the certificate: exact names or `*.example.com` |
| `ca.cert` | CA whose name must appear in the server's CertificateRequest |
| `key.type` | `EC` or `RSA` |
| `offer.on.empty.issuers` | Offer the key when the server sends an empty CA list (default `false`) |

The values are compiled into the module (`build.sh` generates `Config.java`), so rebuild and
reinstall after changing them.

## Limitations

- **WebView**: client cert requests go to the app's `WebViewClient`, which cancels them by default.
- **Cronet, Flutter, Go, Rust**, and anything else with its own TLS stack: there is no Java hook
  point for them.
- **mTLS is not CSRF protection**: any page in a hooked Chrome can make a request to an allowed
  host, and Chrome will authenticate it.
- Root is required. The module trusts whatever runs in the whitelisted apps.

## License

[MIT](LICENSE)
