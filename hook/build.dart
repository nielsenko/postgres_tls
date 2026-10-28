import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

/// Bundles the native library for the target being built.
///
/// A source checkout has a build.zig and compiles with zig through
/// `dart run zig_hook:build`, a dev dependency, so every zig change is
/// built and linked again. The published package carries no build.zig and
/// a prebuilt library per target under `binary/` instead, so consumers
/// need no toolchain. A target without a library gets no asset.
///
/// A `cpu` user define in the root package's pubspec picks the zig `-Dcpu`
/// in a checkout:
///
///     hooks:
///       user_defines:
///         postgres_tls:
///           cpu: x86_64_v3
Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final code = input.config.code;
    final root = input.packageRoot;
    final sdk = code.targetOS == OS.iOS ? code.iOS.targetSdk : null;
    final directory =
        '${code.targetOS.name}-${code.targetArchitecture.name}'
        '${sdk == IOSSdk.iPhoneSimulator ? '-simulator' : ''}';

    final Uri? library;
    if (File.fromUri(root.resolve('build.zig')).existsSync()) {
      final cpu = input.userDefines['cpu'] as String?;
      final result = await Process.run(Platform.resolvedExecutable, [
        'run',
        'zig_hook:build',
        '--os=${code.targetOS.name}',
        '--arch=${code.targetArchitecture.name}',
        if (sdk != null) '--ios-sdk=${sdk.type}',
        '--out=${input.outputDirectory.toFilePath()}',
        '--cache=${input.outputDirectoryShared.toFilePath()}',
        if (cpu != null) '--cpu=$cpu',
      ], workingDirectory: root.toFilePath());
      if (result.exitCode != 0) {
        throw BuildError(
          message:
              'dart run zig_hook:build failed. Run dart pub get in the '
              'checkout if it has not been run.\n'
              '${result.stdout}${result.stderr}',
        );
      }
      final built = jsonDecode(
        (result.stdout as String).trim().split('\n').last,
      ) as Map<String, Object?>;
      for (final path in built['dependencies'] as List) {
        output.dependencies.add(Uri.file(path as String));
      }
      final path = built['library'] as String?;
      library = path == null ? null : Uri.file(path);
    } else {
      final prebuilt = Directory.fromUri(root.resolve('binary/$directory/'));
      final files = prebuilt.existsSync()
          ? prebuilt.listSync().whereType<File>().toList()
          : const <File>[];
      library = files.isEmpty ? null : files.single.uri;
      if (library != null) output.dependencies.add(library);
    }
    if (library == null) return;

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: '${input.packageName}.dart',
        linkMode: DynamicLoadingBundled(),
        file: library,
      ),
    );
  });
}
