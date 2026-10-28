import 'dart:io';

import 'package:postgres/postgres.dart';

import 'postgres_tls_socket.dart';

/// A [TlsConnector] that runs TLS in the native library.
///
/// ```dart
/// ConnectionSettings(
///   sslMode: SslMode.require,
///   tlsConnector: nativeTlsConnector,
/// )
/// ```
///
/// With [SslMode.verifyFull] the server's chain must name [host] and lead
/// to the system's roots. [SslMode.require] accepts any certificate.
Future<Socket> nativeTlsConnector(
  String host,
  int port, {
  required SslMode sslMode,
  required Duration timeout,
}) => PostgresTlsSocket.connect(
  host,
  port,
  timeout: timeout,
  verify: sslMode == SslMode.verifyFull,
);
