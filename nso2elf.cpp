#include "nso.hpp"

#include <iostream>

auto main(std::int32_t argc, const char** argv) -> std::int32_t {
    constexpr auto print_usage = []() -> void {
        std::cout
            << "nso2elf\n"
            << "  Usage:\n"
            << "    nso2elf <options> path_to_nso\n"
            << "\n"
            << "  Basic Options\n"
            << "    --help, -h              print help message\n"
            << "    --output, -o            output filepath\n";
    };

    if (argc < 2) {
        std::cerr << "Too few input arguments\n";
        print_usage();
        return 0;
    }

    const auto path = std::string(argv[argc - 1]);
    if (path == "--help" || path == "-h") {
        print_usage();
        return 0;
    }

    const auto args = std::span(argv + 1, argc - 2);
    std::string outpath = "";

    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto arg = std::string_view(args[i]);
        if (arg.empty()) {
            continue;
        }

        if (arg.starts_with("--")) {
            const auto name = arg.substr(2);

            if (name == "output") {
                if (i++ >= args.size() - 1) {
                    std::cerr << "Expected output path but no arguments remain\n";
                    return 1;
                }
                outpath = args[i];
            } else if (name == "help") {
                print_usage();
                return 0;
            } else {
                std::cerr << "[WARNING] Ignoring unknown argument " << arg << "\n";
            }
        } else if (arg.starts_with('-')) {
            const auto name = arg.substr(1);

            if (name == "o") {
                if (i++ >= args.size() - 1) {
                    std::cerr << "Expected output path but no arguments remain\n";
                    return 1;
                }
                outpath = args[i];
            } else if (name == "h") {
                print_usage();
                return 0;
            } else {
                std::cerr << "[WARNING] Ignoring unknown argument " << arg << "\n";
            }
        } else {
            std::cerr << "[WARNING] Ignoring unknown argument " << arg << "\n";
        }
    }

    NSOFile()
        .loadNSO(path)
        .saveELF(outpath);

    return 0;
}