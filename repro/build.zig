const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The Zig static lib mirroring dwarf-zig (built the same way: link_libc, ReleaseFast).
    const lib = b.addLibrary(.{
        .name = "repro",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("repro.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // A C++ executable that links the Zig lib -- the same shape as kcov.
    const exe = b.addExecutable(.{
        .name = "repro",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    exe.root_module.addCSourceFile(.{ .file = b.path("main.cc") });
    exe.root_module.linkLibrary(lib);
    b.installArtifact(exe);
}
