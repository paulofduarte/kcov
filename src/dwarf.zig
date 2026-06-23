//! DWARF line-table reader backed by `std.debug.Dwarf`, exposed over a C ABI for
//! kcov. It enumerates every `(file, line, address)` row from an ELF binary or a
//! Mach-O `.dSYM`, including DWARF emitted by Zig's self-hosted backend, whose
//! vendor line opcodes libdw/libdwarf reject.

const std = @import("std");
const macho = std.macho;
const posix = std.posix;
const ElfFile = std.debug.ElfFile;
const Dwarf = std.debug.Dwarf;
const LNS = std.dwarf.LNS;
const LNE = std.dwarf.LNE;

fn dz_dbg(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "[dzdbg] " ++ fmt ++ "\n", args) catch return;
    _ = std.c.write(2, s.ptr, s.len);
}

// Native fault diagnostics: report the signal + faulting address on a crash.
extern "c" fn _exit(code: c_int) noreturn;
const SigactionC = extern struct {
    handler: ?*const fn (c_int, ?*const anyopaque, ?*anyopaque) callconv(.c) void,
    mask: u32,
    flags: c_int,
};
extern "c" fn sigaction(sig: c_int, act: ?*const SigactionC, oact: ?*SigactionC) c_int;
fn faultHandler(sig: c_int, info: ?*const anyopaque, ctx: ?*anyopaque) callconv(.c) void {
    var si_addr: usize = 0;
    // Darwin siginfo_t: si_addr lives at byte offset 24.
    if (info) |p| si_addr = @as(*align(1) const usize, @ptrFromInt(@intFromPtr(p) + 24)).*;
    // Darwin x86_64 ucontext: uc_mcontext ptr @48; mcontext __ss.__rip @144.
    var rip: usize = 0;
    if (ctx) |u| {
        const mctx = @as(*align(1) const usize, @ptrFromInt(@intFromPtr(u) + 48)).*;
        if (mctx != 0) rip = @as(*align(1) const usize, @ptrFromInt(mctx + 144)).*;
    }
    dz_dbg("*** FAULT sig={d} si_addr=0x{x} rip=0x{x} ***", .{ sig, si_addr, rip });
    dz_dbg("*** dwarf-zig fns: forEachLine=0x{x} emitRows=0x{x} collectStmtAddrs=0x{x} dz_dbg=0x{x} ***", .{
        @intFromPtr(&forEachLine), @intFromPtr(&emitRows), @intFromPtr(&collectStmtAddrs), @intFromPtr(&dz_dbg),
    });
    _exit(139);
}
fn installFaultHandler() void {
    const act = SigactionC{ .handler = &faultHandler, .mask = 0, .flags = 0x40 }; // SA_SIGINFO
    _ = sigaction(11, &act, null); // SIGSEGV
    _ = sigaction(10, &act, null); // SIGBUS
    _ = sigaction(4, &act, null); // SIGILL
}

/// Invoked once per line-table row. `file` points at `file_len` bytes that are only
/// valid for the duration of the call; the callee must copy what it needs.
pub const LineCallback = *const fn (
    ctx: ?*anyopaque,
    file: [*]const u8,
    file_len: usize,
    line: u32,
    address: u64,
) callconv(.c) void;

/// Report every line-table row of the binary at `path` (`path_len` bytes) to `cb`.
/// Returns 0 on success or a negative error code.
export fn dwarf_zig_for_each_line(
    path: [*]const u8,
    path_len: usize,
    cb: LineCallback,
    ctx: ?*anyopaque,
) callconv(.c) c_int {
    forEachLine(path[0..path_len], cb, ctx) catch |err| return switch (err) {
        error.FileNotFound => -1,
        error.MissingDebugInfo => -2,
        error.InvalidDebugInfo => -3,
        else => -4,
    };
    return 0;
}

fn forEachLine(path: []const u8, cb: LineCallback, ctx: ?*anyopaque) !void {
    installFaultHandler();
    dz_dbg("forEachLine: begin", .{});
    defer dz_dbg("forEachLine: returned (dwarf-zig done)", .{});
    const gpa = std.heap.c_allocator;

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var magic: [4]u8 = undefined;
    if (try file.readPositionalAll(io, &magic, 0) < magic.len) return error.InvalidDebugInfo;

    if (std.mem.eql(u8, &magic, "\x7fELF")) {
        var elf = try ElfFile.load(gpa, io, file, null, &.none);
        defer elf.deinit(gpa);
        const dwarf = &(elf.dwarf orelse return error.MissingDebugInfo);
        try dwarf.open(gpa, elf.endian);
        try emitRows(gpa, dwarf, elf.endian, cb, ctx);
    } else {
        try forEachLineMacho(gpa, io, file, cb, ctx);
    }
}

// Mach-O keeps its DWARF in a `__DWARF` segment (a `.dSYM` companion produced by
// dsymutil, with final link addresses). Extract those sections and read them as ELF.
fn forEachLineMacho(gpa: std.mem.Allocator, io: std.Io, file: std.Io.File, cb: LineCallback, ctx: ?*anyopaque) !void {
    const len: usize = @intCast(try file.length(io));
    const mapped = try posix.mmap(null, len, .{ .READ = true }, .{ .TYPE = .SHARED }, file.handle, 0);
    defer posix.munmap(mapped);

    if (mapped.len < @sizeOf(macho.mach_header_64)) return error.InvalidDebugInfo;
    var reader: std.Io.Reader = .fixed(mapped);
    const hdr = try reader.takeStruct(macho.mach_header_64, .little);
    if (hdr.magic != macho.MH_MAGIC_64) return error.InvalidDebugInfo;

    var sections: Dwarf.SectionArray = @splat(null);
    var it: macho.LoadCommandIterator = try .init(&hdr, mapped[@sizeOf(macho.mach_header_64)..]);
    while (try it.next()) |cmd| switch (cmd.hdr.cmd) {
        .SEGMENT_64 => {
            const seg = cmd.cast(macho.segment_command_64) orelse continue;
            if (!std.mem.eql(u8, seg.segName(), "__DWARF")) continue;
            for (cmd.getSections()) |sect| {
                const idx: usize = inline for (@typeInfo(Dwarf.Section.Id).@"enum".fields, 0..) |s, i| {
                    if (std.mem.eql(u8, "__" ++ s.name, sect.sectName())) break i;
                } else continue;
                if (mapped.len < sect.offset + sect.size) return error.InvalidDebugInfo;
                sections[idx] = .{ .data = mapped[sect.offset..][0..sect.size], .owned = false };
            }
        },
        else => {},
    };

    var dwarf: Dwarf = .{ .sections = sections };
    defer dwarf.deinit(gpa);
    try dwarf.open(gpa, .little);
    dz_dbg("macho: dwarf.open ok -> emitRows", .{});
    try emitRows(gpa, &dwarf, .little, cb, ctx);
}

// Report only statement-boundary rows, matching kcov's libdw backend. std.dwarf
// drops the is_stmt flag, so collect the statement addresses from the line program
// and filter line_table by them; otherwise non-statement rows (closing braces,
// epilogues, at function-end addresses) would count as uncovered lines.
noinline fn emitRows(
    gpa: std.mem.Allocator,
    dwarf: *Dwarf,
    endian: std.builtin.Endian,
    cb: LineCallback,
    ctx: ?*anyopaque,
) !void {
    dz_dbg("emitRows: ENTRY CUs={d} -> collectStmtAddrs", .{dwarf.compile_unit_list.items.len});
    var stmt_addrs = try collectStmtAddrs(gpa, dwarf, endian);
    dz_dbg("emitRows: collectStmtAddrs returned count={d}", .{stmt_addrs.count()});
    defer stmt_addrs.deinit(gpa);

    var path_buf: [std.fs.max_path_bytes * 2]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&path_buf);

    for (dwarf.compile_unit_list.items) |*cu| {
        dwarf.populateSrcLocCache(gpa, endian, cu) catch continue;
        const slc = &cu.src_loc_cache.?;

        var rows = slc.line_table.iterator();
        while (rows.next()) |row| {
            const entry = row.value_ptr.*;
            if (entry.isInvalid()) continue;
            if (!stmt_addrs.contains(row.key_ptr.*)) continue;

            // DWARF < 5 file indices are 1-based; DWARF 5 is 0-based.
            const file_index = entry.file - @intFromBool(slc.version < 5);
            if (file_index >= slc.files.len) continue;
            const file_entry = &slc.files[file_index];

            const dir = if (file_entry.dir_index < slc.directories.len)
                slc.directories[file_entry.dir_index].path
            else
                "";

            fba.reset();
            const file = std.fs.path.join(fba.allocator(), &.{ dir, file_entry.path }) catch continue;
            cb(ctx, file.ptr, file.len, entry.line, row.key_ptr.*);
        }
    }
}

// Replay the line-number program (the VM that std.debug.Dwarf runs internally but
// whose is_stmt flag it does not expose) and collect the addresses of statement rows.
noinline fn collectStmtAddrs(
    gpa: std.mem.Allocator,
    dwarf: *Dwarf,
    endian: std.builtin.Endian,
) !std.AutoHashMapUnmanaged(u64, void) {
    dz_dbg("collectStmtAddrs: ENTRY", .{});
    var set: std.AutoHashMapUnmanaged(u64, void) = .empty;
    errdefer set.deinit(gpa);
    const data = dwarf.section(.debug_line) orelse return set;
    dz_dbg("collectStmtAddrs: debug_line len={d}", .{data.len});

    var reader: std.Io.Reader = .fixed(data);
    while (reader.seek < data.len) {
        const start = reader.seek;
        const header = Dwarf.readUnitHeader(&reader, endian) catch break;
        if (header.unit_length == 0) break;
        const unit_end: usize = @intCast(@as(u64, start) + header.header_length + header.unit_length);
        collectUnit(gpa, &reader, endian, header.format, unit_end, &set) catch {};
        reader.seek = unit_end;
    }
    return set;
}

fn collectUnit(
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    endian: std.builtin.Endian,
    format: std.dwarf.Format,
    unit_end: usize,
    set: *std.AutoHashMapUnmanaged(u64, void),
) !void {
    const version = try reader.takeInt(u16, endian);
    if (version < 2) return;

    var addr_size: u8 = 8; // every supported target is 64-bit
    if (version >= 5) {
        addr_size = try reader.takeByte();
        _ = try reader.takeByte(); // segment selector size
    }

    const prologue_length = if (format == .@"64")
        try reader.takeInt(u64, endian)
    else
        try reader.takeInt(u32, endian);
    const prog_start: usize = @intCast(@as(u64, reader.seek) + prologue_length);

    const min_inst_length: u64 = try reader.takeByte();
    if (min_inst_length == 0) return;
    if (version >= 4) _ = try reader.takeByte(); // maximum operations per instruction
    const default_is_stmt = (try reader.takeByte()) != 0;
    _ = try reader.takeByteSigned(); // line_base (the line value is not tracked)
    const line_range = try reader.takeByte();
    if (line_range == 0) return;
    const opcode_base = try reader.takeByte();
    const std_opcode_lengths = try reader.take(opcode_base - 1);

    reader.seek = prog_start; // skip the directory and file-name tables

    var address: u64 = 0;
    var is_stmt = default_is_stmt;
    while (reader.seek < unit_end) {
        const opcode = try reader.takeByte();
        if (opcode == LNS.extended_op) {
            const op_size = try reader.takeLeb128(u64);
            if (op_size < 1) return;
            switch (try reader.takeByte()) {
                LNE.end_sequence => {
                    address = 0;
                    is_stmt = default_is_stmt;
                },
                LNE.set_address => address = if (addr_size == 8)
                    try reader.takeInt(u64, endian)
                else
                    try reader.takeInt(u32, endian),
                else => try reader.discardAll64(op_size - 1),
            }
        } else if (opcode >= opcode_base) {
            address += min_inst_length * (@as(u64, opcode - opcode_base) / line_range);
            if (is_stmt) try set.put(gpa, address, {});
        } else switch (opcode) {
            LNS.copy => if (is_stmt) try set.put(gpa, address, {}),
            LNS.advance_pc => address += (try reader.takeLeb128(u64)) * min_inst_length,
            LNS.advance_line => _ = try reader.takeLeb128(i64),
            LNS.set_file => _ = try reader.takeLeb128(u64),
            LNS.set_column => _ = try reader.takeLeb128(u64),
            LNS.negate_stmt => is_stmt = !is_stmt,
            LNS.set_basic_block => {},
            LNS.const_add_pc => address += min_inst_length * (@as(u64, 255 - opcode_base) / line_range),
            LNS.fixed_advance_pc => address += try reader.takeInt(u16, endian),
            LNS.set_prologue_end, LNS.set_epilogue_begin => {},
            LNS.set_isa => _ = try reader.takeLeb128(u64),
            else => {
                // Unknown standard opcode (not emitted by Zig): skip its operands.
                if (opcode - 1 < std_opcode_lengths.len) {
                    var i = std_opcode_lengths[opcode - 1];
                    while (i > 0) : (i -= 1) _ = try reader.takeLeb128(u64);
                }
            },
        }
    }
}

fn expectReadsFixture(path: []const u8) !void {
    var found = false;
    const collect = struct {
        fn cb(ctx: ?*anyopaque, file: [*]const u8, file_len: usize, line: u32, _: u64) callconv(.c) void {
            const seen: *bool = @ptrCast(@alignCast(ctx.?));
            if (line > 0 and std.mem.endsWith(u8, file[0..file_len], "fixture.zig")) seen.* = true;
        }
    }.cb;

    try forEachLine(path, collect, &found);
    try std.testing.expect(found);
}

// build.zig builds src/test/fixture.zig and passes the paths via build options.
test "reads line rows from an ELF binary" {
    try expectReadsFixture(@import("build_options").fixture_path);
}

test "reads line rows from a Mach-O .dSYM" {
    const path = @import("build_options").macho_fixture_path;
    if (path.len == 0) return error.SkipZigTest; // only built on a macOS host (needs dsymutil)
    try expectReadsFixture(path);
}
