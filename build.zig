// Builds libpostgres_tls for one target per invocation. zig_hook's Dart
// tool drives it, but its addDartLibrary reads Build.sysroot, which zig
// 0.17 removed, so the library is set up here the same way.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });
    const strip = b.option(bool, "strip", "Strip debug info, as the prebuilt binaries are") orelse false;
    const tls = b.dependency("tls", .{ .target = target, .optimize = optimize });

    const lib = b.addLibrary(.{
        .name = "postgres_tls",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/postgres_tls.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
        }),
    });
    lib.root_module.addImport("tls", tls.module("tls"));
    if (target.result.os.tag.isDarwin()) {
        lib.headerpad_max_install_names = true;
    }
    if (target.result.abi.isAndroid()) {
        lib.link_z_max_page_size = 16384;
    }
    b.installArtifact(lib);
}
