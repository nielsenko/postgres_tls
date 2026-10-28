import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:postgres_tls/postgres_tls.dart';
import 'package:test/test.dart';

import 'src/echo_server.dart';

void main() {
  group('Given a server that answers the SSLRequest with S', () {
    late EchoServer server;
    setUp(() async => server = await EchoServer.start());
    tearDown(() => server.close());

    test('when a message is sent, '
        'then the server echoes it back over TLS', () async {
      final socket = await PostgresTlsSocket.connect('localhost', server.port);
      final echoed = socket.first;
      socket.add([1, 2, 3]);

      expect(await echoed, [1, 2, 3]);
      socket.destroy();
    });

    test('when 4 MiB is sent in one add, '
        'then every byte comes back in order', () async {
      final socket = await PostgresTlsSocket.connect('localhost', server.port);
      final random = Random(1);
      final payload = Uint8List.fromList(
        List.generate(4 << 20, (_) => random.nextInt(256)),
      );
      final echoed = BytesBuilder(copy: false);
      final all = Completer<void>();
      socket.listen((data) {
        echoed.add(data);
        if (echoed.length == payload.length) all.complete();
      });
      socket.add(payload);

      await all.future;
      expect(echoed.takeBytes(), payload);
      socket.destroy();
    });

    test('when the client closes, '
        'then the server has everything it sent', () async {
      final socket = await PostgresTlsSocket.connect('localhost', server.port);
      socket.listen((_) {});
      socket
        ..add([1, 2])
        ..add([3]);
      await socket.close();

      expect(await server.received, [1, 2, 3]);
    });

    test('when verifying against the CA that signed it, '
        'then the connection opens', () async {
      final socket = await PostgresTlsSocket.connect(
        'localhost',
        server.port,
        verify: true,
        trustedRoots: caPem,
      );
      socket.destroy();
    });

    test('when verifying against the system roots, '
        'then connect throws a HandshakeException', () async {
      await expectLater(
        PostgresTlsSocket.connect('localhost', server.port, verify: true),
        throwsA(isA<HandshakeException>()),
      );
    });

    test('when verifying a host the certificate does not name, '
        'then connect throws a HandshakeException', () async {
      await expectLater(
        PostgresTlsSocket.connect(
          '127.0.0.1',
          server.port,
          verify: true,
          trustedRoots: caPem,
        ),
        throwsA(isA<HandshakeException>()),
      );
    });
  });

  test('Given a server that answers the SSLRequest with N, '
      'when connecting, '
      'then connect throws a TlsException', () async {
    final server = await EchoServer.start(sslResponse: 0x4e);
    addTearDown(server.close);

    await expectLater(
      PostgresTlsSocket.connect('localhost', server.port),
      throwsA(isA<TlsException>()),
    );
  });

  test('Given a server that sends bytes after its S, '
      'when connecting, '
      'then connect throws a TlsException', () async {
    final server = await EchoServer.start(trailing: [0x16, 3, 1]);
    addTearDown(server.close);

    await expectLater(
      PostgresTlsSocket.connect('localhost', server.port),
      throwsA(isA<TlsException>()),
    );
  });

  test('Given a server that closes right after the handshake, '
      'when listening, '
      'then the stream ends', () async {
    final server = await EchoServer.start(closeAfterHandshake: true);
    addTearDown(server.close);

    final socket = await PostgresTlsSocket.connect('localhost', server.port);

    expect(await socket.toList(), isEmpty);
    socket.destroy();
  });

  group('Given PostgresTlsOverrides for one endpoint', () {
    late EchoServer server;
    setUp(() async => server = await EchoServer.start());
    tearDown(() => server.close());

    test('when Socket.connect targets that endpoint, '
        'then it returns a PostgresTlsSocket', () async {
      final socket = await IOOverrides.runWithIOOverrides(
        () => Socket.connect('localhost', server.port),
        PostgresTlsOverrides({('localhost', server.port)}),
      );

      expect(socket, isA<PostgresTlsSocket>());
      socket.destroy();
    });

    test('when Socket.connect targets another endpoint, '
        'then it returns a dart:io socket', () async {
      final other = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(other.close);

      final socket = await IOOverrides.runWithIOOverrides(
        () => Socket.connect(InternetAddress.loopbackIPv4, other.port),
        PostgresTlsOverrides({('localhost', server.port)}),
      );

      expect(socket, isNot(isA<PostgresTlsSocket>()));
      socket.destroy();
    });
  });
}
