//! Client TLS for Postgres connections, with no I/O of its own. Dart reads
//! the socket, feeds the ciphertext here and sends what comes back.
//!
//! A Conn belongs to one connection and to one isolate at a time. After
//! each call Dart reads the outcome from the Conn's Header.
const std = @import("std");
const tls = @import("tls");

const Io = std.Io;
const Bundle = tls.config.cert.Bundle;

const allocator = std.heap.smp_allocator;

/// Plain syscalls: the clock, randomness and reading the system's roots.
fn io() Io {
    return Io.Threaded.global_single_threaded.io();
}

/// Two records, so one can arrive while the last is still partial.
const recv_cap = 2 * tls.input_buffer_len;
/// tls.zig decrypts a record in place, and keeps pointing into the
/// ciphertext buffer, when the cleartext buffer is shorter than the
/// record. Room for all of recv means it never has to.
const plain_cap = recv_cap;
const out_cap = 2 * tls.output_buffer_len;

/// What Dart reads after a call.
pub const Header = extern struct {
    /// Ciphertext for the peer from the last handshake, encrypt or close.
    out: [*]u8,
    out_len: usize,
    out_cap: usize,
    /// Cleartext from the last decrypt.
    plain: [*]u8,
    plain_len: usize,
    plain_cap: usize,
    /// The error name after a call returned a negative value.
    err: [*:0]const u8,
};

const Conn = struct {
    header: Header,
    rng: std.Random.IoSource,
    host: []u8 = &.{},
    /// The roots the caller passed, owned by this connection.
    roots: ?Bundle = null,
    state: union(enum) {
        idle,
        handshake: tls.nonblock.Client,
        open: tls.nonblock.Connection,
        failed,
    } = .idle,
    recv_len: usize = 0,
    recv: [recv_cap]u8 = undefined,
    plain: [plain_cap]u8 = undefined,
    out: [out_cap]u8 = undefined,

    fn fail(c: *Conn, err: anyerror) i32 {
        c.header.err = @errorName(err);
        c.state = .failed;
        return -1;
    }

    fn consume(c: *Conn, n: usize) void {
        std.mem.copyForwards(u8, c.recv[0 .. c.recv_len - n], c.recv[n..c.recv_len]);
        c.recv_len -= n;
    }

    fn start(c: *Conn, host: []const u8, verify: bool, roots: []const u8) !void {
        c.host = try allocator.dupe(u8, host);
        const bundle: Bundle = if (!verify)
            .empty
        else if (roots.len > 0) bundle: {
            c.roots = try tls.config.cert.fromSlice(allocator, io(), roots);
            break :bundle c.roots.?;
        } else try systemRoots();
        c.state = .{ .handshake = .init(.{
            .rng = c.rng.interface(),
            .now = Io.Clock.real.now(io()),
            .host = c.host,
            .root_ca = bundle,
            .insecure_skip_verify = !verify,
            .cipher_suites = tls.config.cipher_suites.secure,
            .named_groups = &.{ .x25519, .secp256r1 },
        }) };
    }
};

var system_roots: ?Bundle = null;
var system_roots_mutex: Io.Mutex = .init;

/// The system's roots, read on first use and kept for the process.
fn systemRoots() !Bundle {
    system_roots_mutex.lockUncancelable(io());
    defer system_roots_mutex.unlock(io());
    if (system_roots == null) system_roots = try tls.config.cert.fromSystem(allocator, io());
    return system_roots.?;
}

export fn postgres_tls_new() ?*Conn {
    const c = allocator.create(Conn) catch return null;
    c.* = .{ .header = undefined, .rng = .{ .io = io() } };
    c.header = .{
        .out = &c.out,
        .out_len = 0,
        .out_cap = out_cap,
        .plain = &c.plain,
        .plain_len = 0,
        .plain_cap = plain_cap,
        .err = "",
    };
    return c;
}

export fn postgres_tls_header(c: *Conn) *Header {
    return &c.header;
}

export fn postgres_tls_free(c: *Conn) void {
    if (c.roots) |*roots| roots.deinit(allocator);
    allocator.free(c.host);
    allocator.destroy(c);
}

/// Starts the handshake, sending [host] as the server name, and puts the
/// ClientHello in out. With [verify] the chain must name host and lead to
/// [roots], PEM, or to the system's roots when roots is empty.
export fn postgres_tls_start(
    c: *Conn,
    host: [*]const u8,
    host_len: usize,
    verify: bool,
    roots: [*]const u8,
    roots_len: usize,
) i32 {
    if (c.state != .idle) return c.fail(error.TlsWrongState);
    c.start(host[0..host_len], verify, roots[0..roots_len]) catch |err| return c.fail(err);
    return postgres_tls_handshake(c);
}

/// Copies as much of data[off..][0..len] as there is room for. Returns how
/// many bytes it took.
export fn postgres_tls_feed(c: *Conn, data: [*]const u8, off: usize, len: usize) usize {
    const n = @min(len, recv_cap - c.recv_len);
    @memcpy(c.recv[c.recv_len..][0..n], data[off..][0..n]);
    c.recv_len += n;
    return n;
}

/// Runs the handshake on what was fed and puts what to send in out.
/// Returns 1 once it is done and 0 while it needs more from the peer.
export fn postgres_tls_handshake(c: *Conn) i32 {
    if (c.state != .handshake) return c.fail(error.TlsWrongState);
    const handshake = &c.state.handshake;
    c.header.out_len = 0;
    while (!handshake.done()) {
        const res = handshake.run(
            c.recv[0..c.recv_len],
            c.out[c.header.out_len..],
        ) catch |err| return c.fail(err);
        c.consume(res.recv_pos);
        c.header.out_len += res.send_pos;
        if (res.recv_pos == 0 and res.send_pos == 0) return 0;
    }
    const cipher = handshake.cipher().?;
    c.state = .{ .open = .init(cipher) };
    return 1;
}

/// Decrypts every whole record that was fed into plain. Returns 1 once the
/// peer has sent close_notify and 0 otherwise.
export fn postgres_tls_decrypt(c: *Conn) i32 {
    if (c.state != .open) return c.fail(error.TlsWrongState);
    const conn = &c.state.open;
    var len: usize = 0;
    defer c.header.plain_len = len;
    while (true) {
        const res = conn.decrypt(c.recv[0..c.recv_len], c.plain[len..]) catch |err| return c.fail(err);
        c.consume(res.ciphertext_pos);
        len += res.cleartext.len;
        if (res.closed) return 1;
        if (res.ciphertext_pos == 0) return 0;
    }
}

/// Encrypts as much of data[off..][0..len] as out has room for. Returns
/// how many bytes it took.
export fn postgres_tls_encrypt(c: *Conn, data: [*]const u8, off: usize, len: usize) isize {
    if (c.state != .open) return c.fail(error.TlsWrongState);
    const res = c.state.open.encrypt(data[off..][0..len], &c.out) catch |err| return c.fail(err);
    c.header.out_len = res.ciphertext.len;
    return @intCast(res.cleartext_pos);
}

/// Puts a close_notify alert in out, or nothing when the connection is not
/// open.
export fn postgres_tls_close(c: *Conn) i32 {
    c.header.out_len = 0;
    if (c.state != .open) return 0;
    const alert = c.state.open.close(&c.out) catch |err| return c.fail(err);
    c.header.out_len = alert.len;
    return 0;
}
