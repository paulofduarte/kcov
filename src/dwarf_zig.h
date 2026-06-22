/* C ABI for the dwarf-zig line-table reader (see dwarf.zig). */
#ifndef KCOV_DWARF_ZIG_H
#define KCOV_DWARF_ZIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dwarf_zig_line_callback)(
    void* ctx, const char* file, size_t file_len, uint32_t line, uint64_t address);

/* Report every (file, line, address) row of the binary at `path` (`path_len`
 * bytes) to `cb`. Returns 0 on success or a negative error code. */
int
dwarf_zig_for_each_line(const char* path, size_t path_len, dwarf_zig_line_callback cb, void* ctx);

#ifdef __cplusplus
}
#endif

#endif /* KCOV_DWARF_ZIG_H */
