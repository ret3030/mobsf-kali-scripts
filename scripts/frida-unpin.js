// frida-unpin.js: disable the common TLS trust checks so an intercepting proxy sees the traffic.
// Covers the default TrustManager, OkHttp CertificatePinner and Conscrypt. Load with frida -l.
Java.perform(function () {
  var hooks = 0;

  // 1. Default X509TrustManager: replace with one that trusts everything.
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'dev.unpin.TrustAll',
      implements: [X509TM],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; },
      },
    });
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) {
      init.call(this, km, [TrustManager.$new()], sr);
    };
    hooks++;
  } catch (e) {}

  // 2. OkHttp CertificatePinner: turn the pin check into a no-op.
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
    try {
      CertPinner.check$okhttp.implementation = function () {};
    } catch (e) {}
    hooks++;
  } catch (e) {}

  // 3. Conscrypt / platform TrustManagerImpl verifyChain.
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.checkTrustedRecursive.implementation = function () { return Java.use('java.util.ArrayList').$new(); };
    hooks++;
  } catch (e) {}
  try {
    var TMI2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI2.verifyChain.implementation = function (certs) { return certs; };
    hooks++;
  } catch (e) {}

  console.log('[frida-unpin] installed ' + hooks + ' hook group(s)');
});
