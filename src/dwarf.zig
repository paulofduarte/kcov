//! DWARF line-table reader backed by `std.debug.Dwarf`, exposed over a C ABI for
//! kcov. It enumerates every `(file, line, address)` row in a binary's debug info,
//! including DWARF emitted by Zig's self-hosted backend, whose vendor line opcodes
//! libdw/libdwarf reject.

const std = @import("std");
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

    var elf = try ElfFile.load(gpa, io, file, null, &.none);
    defer elf.deinit(gpa);
    const dwarf = &(elf.dwarf orelse return error.MissingDebugInfo);
    try dwarf.open(gpa, elf.endian);

    try emitRows(gpa, dwarf, elf.endian, cb, ctx);
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

test "reads line rows from a Zig binary" {
    // build.zig builds src/test/fixture.zig for x86_64-linux and passes its path.
    const fixture_path = @import("build_options").fixture_path;

    var found = false;
    const collect = struct {
        fn cb(ctx: ?*anyopaque, file: [*]const u8, file_len: usize, line: u32, _: u64) callconv(.c) void {
            const seen: *bool = @ptrCast(@alignCast(ctx.?));
            if (line > 0 and std.mem.endsWith(u8, file[0..file_len], "fixture.zig")) seen.* = true;
        }
    }.cb;

    try forEachLine(fixture_path, collect, &found);
    try std.testing.expect(found);
}
