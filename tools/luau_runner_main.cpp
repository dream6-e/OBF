// OBF validation runner for the pinned Luau 0.735 source tree.
//
// Repl.cpp supplies the CLI-compatible environment setup. In particular it
// installs loadstring, the filesystem require implementation, opens the
// standard libraries, and calls luaL_sandbox before user code runs. Keeping
// this tiny entry point in our repository makes that environment explicit and
// gives the matrix a stable version probe.

#include "Luau/Flags.h"
#include "Luau/Repl.h"

#include <cstdio>
#include <cstring>

int main(int argc, char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--obf-runtime-version") == 0)
    {
        std::puts("Luau 0.735 (OBF CLI-compatible runner)");
        return 0;
    }

    setLuauFlagsDefault();
    return replMain(argc, argv);
}
