import 'dart:ffi';

import 'package:ffi/ffi.dart';

const _asset = 'package:postgres_tls/postgres_tls.dart';

/// One connection's TLS state in the native library.
final class TlsConn extends Opaque {}

/// What a call leaves for Dart to read, at a fixed place per connection.
final class TlsHeader extends Struct {
  /// Ciphertext for the peer from the last handshake, encrypt or close.
  external Pointer<Uint8> out;
  @Size()
  external int outLen;
  @Size()
  external int outCap;

  /// Cleartext from the last decrypt.
  external Pointer<Uint8> plain;
  @Size()
  external int plainLen;
  @Size()
  external int plainCap;

  /// The error name after a call returned a negative value.
  external Pointer<Utf8> err;
}

@Native<Pointer<TlsConn> Function()>(
  symbol: 'postgres_tls_new',
  assetId: _asset,
  isLeaf: true,
)
external Pointer<TlsConn> tlsNew();

@Native<Pointer<TlsHeader> Function(Pointer<TlsConn>)>(
  symbol: 'postgres_tls_header',
  assetId: _asset,
  isLeaf: true,
)
external Pointer<TlsHeader> tlsHeader(Pointer<TlsConn> conn);

@Native<Void Function(Pointer<TlsConn>)>(
  symbol: 'postgres_tls_free',
  assetId: _asset,
  isLeaf: true,
)
external void tlsFree(Pointer<TlsConn> conn);

/// Not a leaf call: the first one with verification reads the system's
/// roots, and a leaf call would hold up every isolate's GC meanwhile.
@Native<
  Int32 Function(
    Pointer<TlsConn>,
    Pointer<Uint8>,
    Size,
    Bool,
    Pointer<Uint8>,
    Size,
  )
>(symbol: 'postgres_tls_start', assetId: _asset)
external int tlsStart(
  Pointer<TlsConn> conn,
  Pointer<Uint8> host,
  int hostLength,
  bool verify,
  Pointer<Uint8> roots,
  int rootsLength,
);

@Native<Size Function(Pointer<TlsConn>, Pointer<Uint8>, Size, Size)>(
  symbol: 'postgres_tls_feed',
  assetId: _asset,
  isLeaf: true,
)
external int tlsFeed(
  Pointer<TlsConn> conn,
  Pointer<Uint8> data,
  int offset,
  int length,
);

/// Not a leaf call: verifying the server's chain takes a while.
@Native<Int32 Function(Pointer<TlsConn>)>(
  symbol: 'postgres_tls_handshake',
  assetId: _asset,
)
external int tlsHandshake(Pointer<TlsConn> conn);

@Native<Int32 Function(Pointer<TlsConn>)>(
  symbol: 'postgres_tls_decrypt',
  assetId: _asset,
  isLeaf: true,
)
external int tlsDecrypt(Pointer<TlsConn> conn);

@Native<IntPtr Function(Pointer<TlsConn>, Pointer<Uint8>, Size, Size)>(
  symbol: 'postgres_tls_encrypt',
  assetId: _asset,
  isLeaf: true,
)
external int tlsEncrypt(
  Pointer<TlsConn> conn,
  Pointer<Uint8> data,
  int offset,
  int length,
);

@Native<Int32 Function(Pointer<TlsConn>)>(
  symbol: 'postgres_tls_close',
  assetId: _asset,
  isLeaf: true,
)
external int tlsClose(Pointer<TlsConn> conn);
