const std = @import("std");
const zig_hook = @import("zig_hook");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });
    const tls = b.dependency("tls", .{ .target = target, .optimize = optimize });

    const lib = zig_hook.addDartLibrary(b, .{
        .name = "postgres_tls",
        .root_source_file = b.path("src/postgres_tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.root_module.addImport("tls", tls.module("tls"));
}
