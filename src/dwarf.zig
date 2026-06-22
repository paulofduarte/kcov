//! DWARF line-table reader backed by `std.debug.Dwarf`, exposed over a C ABI for
//! kcov. It enumerates every `(file, line, address)` row from an ELF binary or a
//! Mach-O `.dSYM`, including DWARF emitted by Zig's self-hosted backend, whose
//! vendor line opcodes libdw/libdwarf reject.

const std = @import("std");
const macho = std.macho;
const posix = std.posix;
const ElfFile = std.debug.ElfFile;
const Dwarf = std.debug.Dwarf;

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
    try emitRows(gpa, &dwarf, .little, cb, ctx);
}

// Every row is reported, not just statement boundaries: kcov keys coverage on
// (file, line), so the extra non-statement rows collapse onto lines already present.
fn emitRows(
    gpa: std.mem.Allocator,
    dwarf: *Dwarf,
    endian: std.builtin.Endian,
    cb: LineCallback,
    ctx: ?*anyopaque,
) !void {
    var path_buf: [std.fs.max_path_bytes * 2]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&path_buf);

    for (dwarf.compile_unit_list.items) |*cu| {
        dwarf.populateSrcLocCache(gpa, endian, cu) catch continue;
        const slc = &cu.src_loc_cache.?;

        var rows = slc.line_table.iterator();
        while (rows.next()) |row| {
            const entry = row.value_ptr.*;
            if (entry.isInvalid()) continue;

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
