// Minimal C++ host that links and calls the Zig static lib -- the same
// static-lib-into-C++-executable shape as kcov calling dwarf-zig. Build + run on an
// x86_64 macOS host; see README.md.
#include <cstdio>

extern "C" int repro_run(void);

int main()
{
    int rc = repro_run();
    std::printf("repro_run rc=%d\n", rc);
    return rc < 0 ? 1 : 0;
}
