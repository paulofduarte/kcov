const std = @import("std");

const version = std.SemanticVersion.parse(@import("build.zig.zon").version) catch unreachable;

pub fn build(b: *std.Build) void {
    const upstream = b.dependency("kcov", .{});

    // macOS/x86_64: a long-standing Darwin kernel bug corrupts the AVX-512 opmask registers
    // (k0-k7) on signal return, and kcov is a ptrace/mach debugger full of signal handlers --
    // so any AVX-512 code (std's vectorized search in the dwarf-zig reader, clang's
    // auto-vectorized C++) faults mid-run on a native build. Build the whole coverage tool
    // without AVX-512 there; Go disables AVX-512 on darwin for the same reason. Linux/Windows
    // keep the native CPU (AVX-512 is safe there), and a coverage tool needs no SIMD throughput.
    const requested_target = b.standardTargetOptions(.{});
    const target = blk: {
        if (!(requested_target.result.os.tag.isDarwin() and requested_target.result.cpu.arch == .x86_64))
            break :blk requested_target;
        // Drop to baseline x86_64 -> no AVX-512, keeping the rest of the native query
        // so the macOS SDK/frameworks still resolve. Setting only cpu_model is not
        // enough: when kcov is built as a dependency the parent serializes its *native*
        // target, so the query arrives with the host CPU's features (incl. AVX-512) in
        // cpu_features_add, which survive a cpu_model change. Clear the feature sets too,
        // otherwise AVX-512 codegen leaks back in -- and its larger encodings perturb the
        // Mach-O layout enough to trigger a Zig 0.16 linker bug that overwrites the first
        // 16 bytes of the first __text function's prologue (collectStmtAddrs).
        var query = requested_target.query;
        query.cpu_model = .baseline;
        query.cpu_features_add = .empty;
        query.cpu_features_sub = .empty;
        break :blk b.resolveTargetQuery(query);
    };
    const optimize = b.standardOptimizeOption(.{});

    // Third-party C libraries (curl, zlib, transitively mbedtls) are never UB
    // sanitized: kcov is built as Debug only on x86_64-macOS to dodge a Zig
    // linker bug, and a Debug C lib emits __ubsan_handle_* refs that go
    // unresolved against kcov's -fno-sanitize-c. Build them release regardless.
    const cdep_optimize: std.builtin.OptimizeMode =
        if (optimize == .Debug) .ReleaseFast else optimize;

    // const system_daemon = b.option(bool, "system-daemon", "Enable support for full system instrumentation (untested)") orelse false;

    const link_system_zlib = b.systemIntegrationOption("zlib", .{});
    const link_system_binutils = b.systemIntegrationOption("binutils", .{});
    const link_system_elfutils = b.systemIntegrationOption("elfutils", .{});
    const link_system_curl = b.systemIntegrationOption("curl", .{});

    const kcov_sowrapper = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "kcov_sowrapper",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    kcov_sowrapper.root_module.addIncludePath(upstream.path("src/include"));
    kcov_sowrapper.root_module.addCSourceFiles(.{
        .root = upstream.path("."),
        .files = &.{
            "src/solib-parser/phdr_data.c",
            "src/solib-parser/lib.c",
        },
    });

    const bash_execve_redirector = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "bash_execve_redirector",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    bash_execve_redirector.root_module.addCSourceFile(.{ .file = upstream.path("src/engines/bash-execve-redirector.c") });

    const bash_tracefd_cloexec = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "bash_tracefd_cloexec",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    bash_tracefd_cloexec.root_module.addCSourceFile(.{ .file = upstream.path("src/engines/bash-tracefd-cloexec.c") });

    const kcov_system_lib = b.addLibrary(.{
        .name = "kcov_system_lib",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });

    kcov_system_lib.root_module.addIncludePath(upstream.path("src/include"));
    kcov_system_lib.root_module.addCSourceFiles(.{
        .root = upstream.path("."),
        .files = &.{
            "src/engines/system-mode-binary-lib.cc",
            "src/utils.cc",
            "src/system-mode/registration.cc",
        },
    });

    // TODO utilize C23 #embed
    const bin_to_c_source = b.addExecutable(.{
        .name = "bin_to_c_source",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bin_to_c_source.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });

    const library_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.addArtifactArg(kcov_sowrapper);
        run_bin_to_c_source.addArg("__library");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "library.cc" });
    };

    const bash_redirector_library_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.addArtifactArg(bash_execve_redirector);
        run_bin_to_c_source.addArg("bash_redirector_library");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "bash-redirector-library.cc" });
    };

    const bash_cloexec_library_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.addArtifactArg(bash_tracefd_cloexec);
        run_bin_to_c_source.addArg("bash_cloexec_library");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "bash-cloexec-library.cc" });
    };

    const kcov_system_library_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.stdio_limit = .limited(256 * 1024 * 1024); // 256MiB
        run_bin_to_c_source.addArtifactArg(kcov_system_lib);
        run_bin_to_c_source.addArg("kcov_system_library");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "kcov-system-library.cc" });
    };

    const python_helper_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.addFileArg(upstream.path("src/engines/python-helper.py"));
        run_bin_to_c_source.addArg("python_helper");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "python-helper.cc" });
    };

    const bash_helper_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.addFileArg(upstream.path("src/engines/bash-helper.sh"));
        run_bin_to_c_source.addArg("bash_helper");
        run_bin_to_c_source.addFileArg(upstream.path("src/engines/bash-helper-debug-trap.sh"));
        run_bin_to_c_source.addArg("bash_helper_debug_trap");
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "bash-helper.cc" });
    };

    const html_data_files_cc = blk: {
        const run_bin_to_c_source = b.addRunArtifact(bin_to_c_source);
        run_bin_to_c_source.clearEnvironment();
        run_bin_to_c_source.stdio_limit = .limited(32 * 1024 * 1024); // 32MiB
        for (
            [_][]const u8{
                "data/bcov.css",
                "data/amber.png",
                "data/glass.png",
                "data/source-file.html",
                "data/index.html",
                "data/js/handlebars.js",
                "data/js/kcov.js",
                "data/js/jquery.min.js",
                "data/js/jquery.tablesorter.min.js",
                "data/js/jquery.tablesorter.widgets.min.js",
                "data/tablesorter-theme.css",
            },
            [_][]const u8{
                "css_text",
                "icon_amber",
                "icon_glass",
                "source_file_text",
                "index_text",
                "handlebars_text",
                "kcov_text",
                "jquery_text",
                "tablesorter_text",
                "tablesorter_widgets_text",
                "tablesorter_theme_text",
            },
        ) |path, name| {
            run_bin_to_c_source.addFileArg(upstream.path(path));
            run_bin_to_c_source.addArg(name);
        }
        break :blk run_bin_to_c_source.captureStdOut(.{ .basename = "html-data-files.cc" });
    };

    const version_c = blk: {
        const write_files = b.addWriteFiles();
        break :blk write_files.add("version.c", b.fmt("const char *kcov_version = \"{f}\";", .{version}));
    };

    const kcov = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .pic = true,
        .link_libc = true,
        .link_libcpp = true,
        // kcov is a third-party C/C++ tool that ships and runs in release (no UB
        // sanitizer). We build it as Debug only on x86_64-macOS to dodge a Zig
        // self-hosted Mach-O linker bug; Debug otherwise turns kcov's benign C UB
        // (e.g. unaligned reads of Mach-message fields) into hard aborts. Disable
        // the C UB sanitizer so the Debug build behaves like its tested release.
        .sanitize_c = .off,
    });

    const kcov_exe = b.addExecutable(.{
        .name = "kcov",
        .root_module = kcov,
    });
    b.installArtifact(kcov_exe);
    kcov.addIncludePath(upstream.path("src/include"));
    kcov.addCMacro("KCOV_LIBRARY_PREFIX", "/tmp");

    kcov.addCSourceFile(.{ .file = bash_redirector_library_cc });
    kcov.addCSourceFile(.{ .file = bash_cloexec_library_cc });
    kcov.addCSourceFile(.{ .file = python_helper_cc });
    kcov.addCSourceFile(.{ .file = bash_helper_cc });
    kcov.addCSourceFile(.{ .file = kcov_system_library_cc });
    kcov.addCSourceFile(.{ .file = html_data_files_cc });
    kcov.addCSourceFile(.{ .file = version_c });

    // TODO test Coveralls support
    kcov.addCSourceFile(.{ .file = upstream.path("src/writers/coveralls-writer.cc") });
    // kcov.addCSourceFile(.{ .file = upstream.path("src/writers/dummy-coveralls-writer.cc") });

    // The libbfd disassembler is for the ELF/ptrace engine and pulls in <elf.h>, which
    // does not exist on macOS; Darwin uses the mach engine, so fall back to the dummy.
    if (target.result.cpu.arch.isX86() and !target.result.os.tag.isDarwin()) {
        if (link_system_binutils) {
            kcov.linkSystemLibrary("bfd", .{});
            kcov.linkSystemLibrary("opcodes", .{});
        } else if (b.lazyDependency("binutils", .{
            .target = target,
            .optimize = optimize,
        })) |binutils_dependency| {
            kcov.linkLibrary(binutils_dependency.artifact("bfd"));
            kcov.linkLibrary(binutils_dependency.artifact("opcodes"));
        }
        kcov.addCSourceFile(.{ .file = upstream.path("src/parsers/bfd-disassembler.cc") });
        kcov.addCMacro("ATTRIBUTE_FPTR_PRINTF_2", "ATTRIBUTE_FPTR_PRINTF(2, 3)");
        kcov.addCMacro("KCOV_HAS_LIBBFD", "1");
        kcov.addCMacro("KCOV_LIBFD_DISASM_STYLED", "1"); // TODO?
        kcov.addCMacro("PACKAGE", "1");
        kcov.addCMacro("PACKAGE_VERSION", "1");
    } else {
        kcov.addCSourceFile(.{ .file = upstream.path("src/parsers/dummy-disassembler.cc") });
        kcov.addCMacro("KCOV_HAS_LIBBFD", "0");
        kcov.addCMacro("KCOV_LIBFD_DISASM_STYLED", "0");
    }

    kcov.addCSourceFiles(.{
        .root = upstream.path("src"),
        .files = &.{
            "capabilities.cc",
            "collector.cc",
            "configuration.cc",
            "engine-factory.cc",
            "engines/bash-engine.cc",
            "engines/system-mode-engine.cc",
            "engines/system-mode-file-format.cc",
            "engines/python-engine.cc",
            "filter.cc",
            "main.cc",
            "merge-file-parser.cc",
            "output-handler.cc",
            "parser-manager.cc",
            "reporter.cc",
            "source-file-cache.cc",
            "utils.cc",
            "writers/cobertura-writer.cc",
            "writers/codecov-writer.cc",
            "writers/json-writer.cc",
            "writers/html-writer.cc",
            "writers/sonarqube-xml-writer.cc",
            "writers/writer-base.cc",
            "system-mode/file-data.cc",
        },
    });

    // dwarf-zig: reads DWARF line tables via Zig's std.debug.Dwarf, replacing libdw.
    const dwarf_zig = b.addLibrary(.{
        .name = "dwarf_zig",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dwarf.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // Bridge test: build a fixture for x86_64-linux (self-hosted DWARF, which libdw
    // rejects) and check dwarf-zig reads its line table.
    const fixture = b.addExecutable(.{
        .name = "dwarf_zig_fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test/fixture.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux }),
            .optimize = .Debug,
        }),
    });
    const test_options = b.addOptions();
    test_options.addOptionPath("fixture_path", fixture.getEmittedBin());

    // The Mach-O path is exercised only on a macOS host, where dsymutil produces the
    // .dSYM whose DWARF the bridge reads.
    if (@import("builtin").os.tag == .macos) {
        const macho_fixture = b.addExecutable(.{
            .name = "dwarf_zig_fixture_macho",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test/fixture.zig"),
                .target = b.resolveTargetQuery(.{}),
                .optimize = .Debug,
            }),
        });
        const dsymutil = b.addSystemCommand(&.{ "dsymutil", "--flat" });
        dsymutil.addFileArg(macho_fixture.getEmittedBin());
        dsymutil.addArg("-o");
        test_options.addOptionPath("macho_fixture_path", dsymutil.addOutputFileArg("fixture.dwarf"));
    } else {
        test_options.addOption([]const u8, "macho_fixture_path", "");
    }

    const dwarf_zig_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dwarf.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    dwarf_zig_test.root_module.addOptions("build_options", test_options);
    const test_step = b.step("test", "Run dwarf-zig tests");
    test_step.dependOn(&b.addRunArtifact(dwarf_zig_test).step);

    switch (target.result.os.tag) {
        .linux, .freebsd => |os_tag| {
            // ELF_SRCS
            kcov.addCSourceFiles(.{
                .root = upstream.path("."),
                .files = &.{
                    "src/engines/ptrace.cc",
                    if (os_tag == .linux)
                        "src/engines/ptrace_linux.cc"
                    else
                        "src/engines/ptrace_freebsd.cc",
                    "src/parsers/elf.cc",
                    "src/parsers/elf-parser.cc",
                    "src/solib-handler.cc",
                    "src/solib-parser/phdr_data.c",
                },
            });
            if (os_tag == .linux) {
                kcov.addCSourceFile(.{ .file = upstream.path("src/engines/kernel-engine.cc") });
            }

            // SOLIB_generated
            kcov.addCSourceFile(.{ .file = library_cc });

            // DWARF line tables via dwarf-zig instead of libdw.
            kcov.addIncludePath(upstream.path("src/parsers"));
            kcov.addIncludePath(b.path("src"));
            kcov.addCSourceFile(.{ .file = b.path("src/parsers/dwarf-zig.cc") });
            kcov.linkLibrary(dwarf_zig);
        },
        .ios,
        .macos,
        .watchos,
        .tvos,
        => {
            // ELF_SRCS
            kcov.addCSourceFile(.{ .file = upstream.path("src/dummy-solib-handler.cc") });

            // MACHO_SRCS
            kcov.addCSourceFiles(.{
                .root = upstream.path("."),
                .files = &.{
                    "src/engines/mach-engine.cc",
                    "src/engines/osx/mach_excServer.c",
                },
            });

            // DWARF line tables (from the .dSYM) via dwarf-zig instead of libdwarf.
            kcov.addIncludePath(upstream.path("src/parsers"));
            kcov.addIncludePath(b.path("src"));
            kcov.addCSourceFile(.{ .file = b.path("src/parsers/macho-parser-zig.cc") });
            kcov.linkLibrary(dwarf_zig);
        },
        else => |os_tag| std.debug.panic("unsupported os '{s}'", .{@tagName(os_tag)}),
    }

    var kcov_system_daemon: ?*std.Build.Step.Compile = null;

    if (target.result.os.tag == .linux) {
        const system_daemon = b.addExecutable(.{
            .name = "kcov-system-daemon",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .link_libcpp = true,
            }),
        });
        b.installArtifact(system_daemon);
        system_daemon.root_module.addIncludePath(upstream.path("src/include"));
        system_daemon.root_module.addCSourceFile(.{ .file = version_c });
        system_daemon.root_module.addCSourceFiles(.{
            .root = upstream.path("src"),
            .files = &.{
                "configuration.cc",
                "dummy-solib-handler.cc",
                "engine-factory.cc",
                "engines/system-mode-file-format.cc",
                "engines/ptrace.cc",
                "engines/ptrace_linux.cc",
                "filter.cc",
                "main-system-daemon.cc",
                "parser-manager.cc",
                "system-mode/file-data.cc",
                "system-mode/registration.cc",
                "utils.cc",
            },
        });

        kcov_system_daemon = system_daemon;
    }

    const run_kcov = b.addRunArtifact(kcov_exe);
    run_kcov.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_kcov.addArgs(args);
    }

    const run_step = b.step("run", "Run kcov");
    run_step.dependOn(&run_kcov.step);

    const line2addr = b.addExecutable(.{
        .name = "line2addr",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    line2addr.root_module.addIncludePath(upstream.path("src/include"));
    line2addr.root_module.addCSourceFile(.{ .file = upstream.path("tools/line2addr.cc") });
    line2addr.root_module.addCSourceFiles(.{
        .root = upstream.path("src"),
        .files = &.{
            "capabilities.cc",
            "configuration.cc",
            "filter.cc",
            "parsers/dwarf.cc",
            "parsers/elf-parser.cc",
            "parsers/elf.cc",
            "parsers/dummy-disassembler.cc",
            "parser-manager.cc",
            "utils.cc",
        },
    });

    const run_line2addr = b.addRunArtifact(kcov_exe);

    if (b.args) |args| {
        run_line2addr.addArgs(args);
    }

    const line2addr_step = b.step("line2addr", "Run line2addr");
    line2addr_step.dependOn(&run_line2addr.step);

    if (link_system_curl) {
        kcov.linkSystemLibrary("curl", .{});
        kcov_system_lib.root_module.linkSystemLibrary("curl", .{});
        if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkSystemLibrary("curl", .{});
        line2addr.root_module.linkSystemLibrary("curl", .{});
    } else if (b.lazyDependency("curl", .{
        .target = target,
        .optimize = cdep_optimize,

        // allyourcodebase/openssl only works on x86_64-linux
        .@"use-mbedtls" = true,

        // These dependencies would require linking system libraries
        .nghttp2 = false,
        .libidn2 = false,
        .libpsl = false,
        .libssh2 = false,
        .@"disable-ldap" = true,
    })) |curl_dependency| {
        if (b.lazyImport(@This(), "curl")) |curl_builder| {
            // https://github.com/ziglang/zig/issues/20377
            const libCurl = curl_builder.artifact(curl_dependency, .lib);
            kcov.linkLibrary(libCurl);
            kcov_system_lib.root_module.linkLibrary(libCurl);
            if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkLibrary(libCurl);
            line2addr.root_module.linkLibrary(libCurl);
        }
    }

    if (link_system_zlib) {
        kcov.linkSystemLibrary("z", .{});
        kcov_system_lib.root_module.linkSystemLibrary("z", .{});
        if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkSystemLibrary("z", .{});
        line2addr.root_module.linkSystemLibrary("z", .{});
    } else if (b.lazyDependency("zlib", .{
        .target = target,
        .optimize = cdep_optimize,
    })) |zlib_dependency| {
        kcov.linkLibrary(zlib_dependency.artifact("z"));
        kcov_system_lib.root_module.linkLibrary(zlib_dependency.artifact("z"));
        if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkLibrary(zlib_dependency.artifact("z"));
        line2addr.root_module.linkLibrary(zlib_dependency.artifact("z"));
    }

    if (target.result.os.tag == .linux) {
        if (link_system_elfutils) {
            kcov.linkSystemLibrary("elf", .{});
            if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkSystemLibrary("elf", .{});
            if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkSystemLibrary("dw", .{});
            line2addr.root_module.linkSystemLibrary("elf", .{});
            line2addr.root_module.linkSystemLibrary("dw", .{});
        } else if (b.lazyDependency("elfutils", .{
            .target = target,
            .optimize = optimize,
        })) |elfutils_dependency| {
            kcov.linkLibrary(elfutils_dependency.artifact("elf"));
            // elf-parser.cc includes libdw headers but uses no libdw symbols; the
            // line tables come from dwarf-zig, so provide the headers without libdw.
            kcov.addIncludePath(elfutils_dependency.artifact("dw").getEmittedIncludeTree());
            if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkLibrary(elfutils_dependency.artifact("elf"));
            if (kcov_system_daemon) |system_daemon| system_daemon.root_module.linkLibrary(elfutils_dependency.artifact("dw"));
            line2addr.root_module.linkLibrary(elfutils_dependency.artifact("elf"));
            line2addr.root_module.linkLibrary(elfutils_dependency.artifact("dw"));
        }
    }
}
