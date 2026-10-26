// SPDX-License-Identifier: MIT
#include <iostream>
#include <string>
#include <vector>

#include "app.hpp"

int main(int argc, char** argv) {
    const std::vector<std::string> args(argv + 1, argv + argc);
    return wifi_analyze_cli::run(args, std::cin, std::cout, std::cerr);
}
