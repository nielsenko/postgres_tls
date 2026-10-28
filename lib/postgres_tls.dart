/// TLS for package:postgres connections, run natively by tls.zig instead of
/// dart:io's SecureSocket.
library;

export 'src/native_tls_connector.dart';
export 'src/postgres_tls_socket.dart';
