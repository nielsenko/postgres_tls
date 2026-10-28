/// TLS for package:postgres connections, run natively by tls.zig instead of
/// dart:io's SecureSocket.
library;

export 'src/postgres_tls_overrides.dart';
export 'src/postgres_tls_socket.dart';
