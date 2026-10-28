import 'dart:io';

import 'postgres_tls_socket.dart';

/// Opens [PostgresTlsSocket]s for `Socket.connect` calls to [endpoints],
/// and leaves every other call to dart:io.
///
/// package:postgres opens its connections through `Socket.connect`. Give
/// it `SslMode.disable` for these endpoints: the socket asks for TLS and
/// runs the handshake itself, and package:postgres sees plain bytes.
///
/// ```dart
/// IOOverrides.global = PostgresTlsOverrides({('db.example.com', 5432)});
/// ```
final class PostgresTlsOverrides extends IOOverrides {
  PostgresTlsOverrides(
    Iterable<(String host, int port)> endpoints, {
    this.verify = false,
    this.trustedRoots,
  }) : _endpoints = endpoints.toSet();

  final Set<(String, int)> _endpoints;

  /// Passed to [PostgresTlsSocket.connect].
  final bool verify;

  /// Passed to [PostgresTlsSocket.connect].
  final List<int>? trustedRoots;

  @override
  Future<Socket> socketConnect(
    host,
    int port, {
    sourceAddress,
    int sourcePort = 0,
    Duration? timeout,
  }) {
    if (host is String && _endpoints.contains((host, port))) {
      return PostgresTlsSocket.connect(
        host,
        port,
        timeout: timeout,
        verify: verify,
        trustedRoots: trustedRoots,
      );
    }
    return super.socketConnect(
      host,
      port,
      sourceAddress: sourceAddress,
      sourcePort: sourcePort,
      timeout: timeout,
    );
  }
}
