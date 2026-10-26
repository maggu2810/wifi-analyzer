// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace wifi_analyze_cli {

/// Exit codes (docs/cli.md).
enum ExitCode : int {
    exit_ok = 0,
    exit_usage = 1,
    exit_input = 3,
    exit_oui = 4,
};

/// Runs the CLI with arguments (without program name). Streams are injectable for tests.
int run(const std::vector<std::string>& args, std::istream& in, std::ostream& out,
        std::ostream& err);

} // namespace wifi_analyze_cli
