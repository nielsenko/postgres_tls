# postgres_tls

TLS for [package:postgres](https://pub.dev/packages/postgres) connections,
run by [tls.zig](https://github.com/lalinsky/tls.zig) in a native library
instead of dart:io's `SecureSocket`.

`SecureSocket` sends every chunk through dart:io's IO service and back as
an isolate message, and then announces it with a zero-duration timer.
That is three trips through the event loop per chunk, against one for a
plain socket. On a busy isolate each trip waits behind everything else
in the queue. `PostgresTlsSocket` reads the plain socket and encrypts and
decrypts with synchronous FFI calls on the isolate's own thread.

```dart
final pool = Pool.withEndpoints(
  [Endpoint(host: 'db.example.com', database: 'app', ...)],
  settings: PoolSettings(
    sslMode: SslMode.require,
    tlsConnector: nativeTlsConnector,
  ),
);
```

package:postgres hands the connection to `nativeTlsConnector`, which sends
the SSLRequest and runs the handshake with the endpoint's host as the
server name. With `SslMode.verifyFull` the chain must name the host and
lead to the system's roots. `SslMode.require` accepts any certificate.
For other roots, call `PostgresTlsSocket.connect` with `trustedRoots`
from a connector of your own.

`ConnectionSettings.tlsConnector` is not in a released package:postgres
yet, so `pubspec.yaml` overrides postgres with a checkout that has it.

## Building

The hook builds the library with zig through
[zig_hook](https://github.com/nielsenko/zig_hook). The zig on `PATH` must
be the version in `build.zig.zon`, or anyzig. The library is compiled
for CPUs with hardware AES: AES-NI, PCLMULQDQ and AVX on x64, the ARMv8
crypto extensions on arm64.
