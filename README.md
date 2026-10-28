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
IOOverrides.global = PostgresTlsOverrides({('db.example.com', 5432)});

final pool = Pool.withEndpoints(
  [Endpoint(host: 'db.example.com', database: 'app', ...)],
  settings: PoolSettings(sslMode: SslMode.disable),
);
```

package:postgres opens its sockets through `Socket.connect`, which the
overrides answer with a `PostgresTlsSocket` for the listed endpoints. That
socket sends the SSLRequest and runs the handshake itself, so
package:postgres must not: give it `SslMode.disable`. The server name
is the endpoint's host.

By default any certificate passes, as with `SslMode.require`. With
`verify: true` the chain must name the host and lead to the system's
roots, or to `trustedRoots` when given.

## Building

The hook builds the library with zig through
[zig_hook](https://github.com/nielsenko/zig_hook). The zig on `PATH` must
be the version in `build.zig.zon`, or anyzig. The library is compiled
for CPUs with hardware AES: AES-NI, PCLMULQDQ and AVX on x64, the ARMv8
crypto extensions on arm64.
