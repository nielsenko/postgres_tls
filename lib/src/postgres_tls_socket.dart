import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native.dart';

enum _Phase { sslResponse, handshake, open, closed }

/// A [Socket] to a Postgres server whose bytes travel over TLS that the
/// native library runs.
///
/// Encryption and decryption are synchronous calls on the isolate's own
/// thread, so a chunk read or written costs one trip through the event
/// loop, as on a plain socket. dart:io's SecureSocket makes three.
final class PostgresTlsSocket extends Stream<Uint8List>
    implements Socket, Finalizable {
  PostgresTlsSocket._(this._raw, this._host, this._verify, this._roots)
    : _conn = tlsNew() {
    if (_conn == nullptr) throw OutOfMemoryError();
    _header = tlsHeader(_conn).ref;
    _out = _header.out.asTypedList(_header.outCap);
    _plain = _header.plain.asTypedList(_header.plainCap);
    _finalizer.attach(this, _conn.cast(), detach: this);
    _raw.listen(_onEvent, onError: _fail);
    _write(_sslRequest, _sslRequest.length);
  }

  /// Connects to the Postgres server at [host] and [port], asks it for TLS
  /// and runs the handshake, with [host] as the server name.
  ///
  /// With [verify] the server's chain must name [host] and lead to one of
  /// [trustedRoots], PEM, or to the system's roots when that is null.
  /// Without it any certificate passes, as with libpq's `sslmode=require`.
  static Future<PostgresTlsSocket> connect(
    String host,
    int port, {
    Duration? timeout,
    bool verify = false,
    List<int>? trustedRoots,
  }) async {
    final raw = await RawSocket.connect(host, port, timeout: timeout);
    raw.setOption(SocketOption.tcpNoDelay, true);
    final socket = PostgresTlsSocket._(raw, host, verify, trustedRoots);
    try {
      final ready = socket._ready.future;
      await (timeout == null ? ready : ready.timeout(timeout));
    } catch (_) {
      socket.destroy();
      rethrow;
    }
    return socket;
  }

  static final _finalizer = NativeFinalizer(
    Native.addressOf<NativeFunction<Void Function(Pointer<TlsConn>)>>(
      tlsFree,
    ).cast(),
  );

  /// Length 8, then the SSLRequest code 80877103.
  static final _sslRequest = Uint8List.fromList([0, 0, 0, 8, 4, 210, 22, 47]);

  final RawSocket _raw;
  final String _host;
  final bool _verify;
  final List<int>? _roots;
  final Pointer<TlsConn> _conn;
  late final TlsHeader _header;
  late final Uint8List _out;
  late final Uint8List _plain;

  var _phase = _Phase.sslResponse;
  final _ready = Completer<void>();
  final _done = Completer<void>();
  late final _incoming = StreamController<Uint8List>(
    onPause: () => _raw.readEventsEnabled = false,
    onResume: () => _raw.readEventsEnabled = true,
  );

  /// Ciphertext the kernel had no room for yet.
  final _pending = ListQueue<Uint8List>();
  var _pendingOffset = 0;
  Completer<void>? _flushed;
  var _closing = false;
  var _readClosed = false;
  var _writeClosed = false;

  @override
  Encoding encoding = utf8;

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _incoming.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  void _onEvent(RawSocketEvent event) {
    switch (event) {
      case RawSocketEvent.read:
        _onRead();
      case RawSocketEvent.write:
        _onWritable();
      case RawSocketEvent.readClosed:
      case RawSocketEvent.closed:
        _onReadClosed();
    }
  }

  void _onRead() {
    if (_phase == _Phase.closed) return;
    final data = _raw.read();
    if (data == null || data.isEmpty) return;
    if (_phase == _Phase.sslResponse) return _onSslResponse(data);
    var offset = 0;
    while (offset < data.length) {
      final n = tlsFeed(_conn, data.address, offset, data.length - offset);
      if (n == 0) return _fail(const TlsException('TLS input overflow'));
      offset += n;
      if (!_process()) return;
    }
  }

  void _onSslResponse(Uint8List data) {
    if (data[0] != 0x53) {
      return _fail(const TlsException('The server does not support SSL'));
    }
    // Bytes after the 'S' came before the handshake, so nothing vouches
    // for them (CVE-2021-23222).
    if (data.length > 1) {
      return _fail(
        const TlsException('The server sent data before the TLS handshake'),
      );
    }
    _phase = _Phase.handshake;
    final host = utf8.encode(_host);
    final roots = _roots ?? const <int>[];
    final hostPointer = malloc<Uint8>(host.length);
    final rootsPointer = malloc<Uint8>(roots.length);
    hostPointer.asTypedList(host.length).setAll(0, host);
    rootsPointer.asTypedList(roots.length).setAll(0, roots);
    final result = tlsStart(
      _conn,
      hostPointer,
      host.length,
      _verify,
      rootsPointer,
      roots.length,
    );
    malloc
      ..free(hostPointer)
      ..free(rootsPointer);
    if (result < 0) return _fail(HandshakeException(_error()));
    _write(_out, _header.outLen);
  }

  /// Runs what was fed through the handshake, then decrypts it. False once
  /// the socket has failed or the peer has closed.
  bool _process() {
    if (_phase == _Phase.handshake) {
      final result = tlsHandshake(_conn);
      if (result < 0) {
        _fail(HandshakeException(_error()));
        return false;
      }
      _write(_out, _header.outLen);
      if (result == 0) return true;
      _phase = _Phase.open;
      _ready.complete();
    }
    final result = tlsDecrypt(_conn);
    if (result < 0) {
      _fail(TlsException(_error()));
      return false;
    }
    final length = _header.plainLen;
    if (length > 0) _incoming.add(_plain.sublist(0, length));
    if (result == 0) return true;
    _onReadClosed();
    return false;
  }

  String _error() => 'TLS error: ${_header.err.toDartString()}';

  @override
  void add(List<int> data) {
    if (_phase != _Phase.open || _closing) return;
    final bytes = data is Uint8List ? data : Uint8List.fromList(data);
    var offset = 0;
    while (offset < bytes.length) {
      final n = tlsEncrypt(_conn, bytes.address, offset, bytes.length - offset);
      if (n < 0) return _fail(TlsException(_error()));
      offset += n;
      _write(_out, _header.outLen);
    }
  }

  /// Sends [length] bytes of [data], keeping a copy of what the kernel
  /// does not take.
  void _write(Uint8List data, int length) {
    if (length == 0) return;
    var written = 0;
    if (_pending.isEmpty) {
      try {
        written = _raw.write(data, 0, length);
      } on SocketException catch (e) {
        return _fail(e);
      }
      if (written == length) return;
    }
    _pending.add(data.sublist(written, length));
    _raw.writeEventsEnabled = true;
  }

  void _onWritable() {
    if (_phase == _Phase.closed) return;
    while (_pending.isNotEmpty) {
      final chunk = _pending.first;
      try {
        _pendingOffset += _raw.write(chunk, _pendingOffset);
      } on SocketException catch (e) {
        return _fail(e);
      }
      if (_pendingOffset < chunk.length) {
        _raw.writeEventsEnabled = true;
        return;
      }
      _pending.removeFirst();
      _pendingOffset = 0;
    }
    _flushed?.complete();
    _flushed = null;
    if (_closing) _closeWrite();
  }

  void _onReadClosed() {
    if (_readClosed) return;
    _readClosed = true;
    if (!_ready.isCompleted) {
      return _fail(
        const HandshakeException('The server closed during the handshake'),
      );
    }
    _incoming.close();
    if (_writeClosed) _dispose();
  }

  /// Sends close_notify and then closes the sending side. The receiving
  /// side stays open until the peer closes it.
  @override
  Future<void> close() {
    if (_phase == _Phase.open && !_closing) {
      _closing = true;
      if (tlsClose(_conn) < 0) {
        _fail(TlsException(_error()));
      } else {
        _write(_out, _header.outLen);
        if (_pending.isEmpty) _closeWrite();
      }
    }
    return _done.future;
  }

  void _closeWrite() {
    _writeClosed = true;
    _raw.shutdown(SocketDirection.send);
    if (_readClosed) {
      _dispose();
    } else if (!_done.isCompleted) {
      _done.complete();
    }
  }

  @override
  void destroy() => _dispose();

  void _fail(Object error) {
    if (_phase == _Phase.closed) return;
    if (!_ready.isCompleted) {
      _ready.completeError(error);
    } else if (!_incoming.isClosed) {
      _incoming.addError(error);
    }
    _dispose();
  }

  void _dispose() {
    if (_phase == _Phase.closed) return;
    _phase = _Phase.closed;
    _raw.close();
    _incoming.close();
    _pending.clear();
    _flushed?.complete();
    _flushed = null;
    if (!_done.isCompleted) _done.complete();
    _finalizer.detach(this);
    tlsFree(_conn);
  }

  @override
  Future<void> flush() {
    if (_pending.isEmpty) return Future.value();
    return (_flushed ??= Completer<void>()).future;
  }

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.forEach(add);

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      throw UnsupportedError('Cannot send errors on sockets');

  @override
  void write(Object? object) => add(encoding.encode('$object'));

  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) =>
      write(objects.join(separator));

  @override
  void writeln([Object? object = '']) => write('$object\n');

  @override
  void writeCharCode(int charCode) => write(String.fromCharCode(charCode));

  @override
  bool setOption(SocketOption option, bool enabled) =>
      _raw.setOption(option, enabled);

  @override
  Uint8List getRawOption(RawSocketOption option) => _raw.getRawOption(option);

  @override
  void setRawOption(RawSocketOption option) => _raw.setRawOption(option);

  @override
  int get port => _raw.port;

  @override
  int get remotePort => _raw.remotePort;

  @override
  InternetAddress get address => _raw.address;

  @override
  InternetAddress get remoteAddress => _raw.remoteAddress;
}
