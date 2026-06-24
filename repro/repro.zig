//! Minimal standalone reproducer for the native x86_64-macOS crash seen when dwarf-zig
//! (a Zig static lib) is linked into the kcov C++ binary and executed natively: a SIGSEGV
//! on *entry* to a `noinline` function that returns an error-union-of-struct
//! (`!std.AutoHashMapUnmanaged(...)`), faulting on a truncated 32-bit pointer
//! (si_addr ~ 0xf0000032) at the function's +5 prologue offset.
//!
//! This lib mirrors dwarf-zig's `collectStmtAddrs`: same return shape (which forces the
//! error-return-trace frame + a struct sret), same `noinline`, same std touchpoints
//! (c_allocator, std.fmt, std.c.write). main.cc links it into a C++ executable -- the same
//! static-lib-into-C++-exe shape as kcov. Build + run natively on an x86_64 macOS host; if
//! it prints `*** FAULT ... ***`, the crash is reproduced with no kcov involved, isolating
//! it to a zig/LLVM codegen-or-relocation bug.

const std = @import("std");

fn dbg(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "[repro] " ++ fmt ++ "\n", args) catch return;
    _ = std.c.write(2, s.ptr, s.len);
}

// Self-reporting fault handler (identical to the dwarf-zig debug build): prints the signal,
// the faulting address (siginfo si_addr @ +24) and the instruction pointer (ucontext ->
// mcontext @ +48 -> __ss.__rip @ +144 on Darwin x86_64).
extern "c" fn _exit(code: c_int) noreturn;
const SigactionC = extern struct {
    handler: ?*const fn (c_int, ?*const anyopaque, ?*anyopaque) callconv(.c) void,
    mask: u32,
    flags: c_int,
};
extern "c" fn sigaction(sig: c_int, act: ?*const SigactionC, oact: ?*SigactionC) c_int;
fn faultHandler(sig: c_int, info: ?*const anyopaque, ctx: ?*anyopaque) callconv(.c) void {
    var si_addr: usize = 0;
    if (info) |p| si_addr = @as(*align(1) const usize, @ptrFromInt(@intFromPtr(p) + 24)).*;
    var rip: usize = 0;
    if (ctx) |u| {
        const mctx = @as(*align(1) const usize, @ptrFromInt(@intFromPtr(u) + 48)).*;
        if (mctx != 0) rip = @as(*align(1) const usize, @ptrFromInt(mctx + 144)).*;
    }
    dbg("*** FAULT sig={d} si_addr=0x{x} rip=0x{x} collectStmtAddrs=0x{x} (rip-base={d}) ***", .{
        sig, si_addr, rip, @intFromPtr(&collectStmtAddrs), rip -% @intFromPtr(&collectStmtAddrs),
    });
    _exit(139);
}
fn installFaultHandler() void {
    const act = SigactionC{ .handler = &faultHandler, .mask = 0, .flags = 0x40 }; // SA_SIGINFO
    _ = sigaction(11, &act, null); // SIGSEGV
    _ = sigaction(10, &act, null); // SIGBUS
    _ = sigaction(4, &act, null); // SIGILL
}

/// C-ABI entry, called from main.cc -- the analogue of dwarf_zig_for_each_line.
export fn repro_run() callconv(.c) c_int {
    installFaultHandler();
    dbg("repro_run: begin -> collectStmtAddrs", .{});
    var set = collectStmtAddrs(std.heap.c_allocator) catch return -1;
    defer set.deinit(std.heap.c_allocator);
    dbg("repro_run: collectStmtAddrs returned count={d}", .{set.count()});
    return @intCast(@as(u32, @truncate(set.count())));
}

// Mirrors dwarf-zig's collectStmtAddrs: `noinline`, returns `!AutoHashMapUnmanaged(u64, void)`
// by value. The error-union-of-struct return is what makes the compiler emit the prologue
// (error-return-trace frame + struct sret) where the native fault lands at +5.
noinline fn collectStmtAddrs(gpa: std.mem.Allocator) !std.AutoHashMapUnmanaged(u64, void) {
    dbg("collectStmtAddrs: ENTRY", .{});
    var set: std.AutoHashMapUnmanaged(u64, void) = .empty;
    errdefer set.deinit(gpa);
    var i: u64 = 0;
    while (i < 1024) : (i += 1) try set.put(gpa, i *% 0x9e3779b97f4a7c15, {});
    return set;
}
