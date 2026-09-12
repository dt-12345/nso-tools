#include "nxo.hpp"

#include <cstdint>
#include <iostream>
#include <span>
#include <string>

static auto ParseHexit(const char c) -> std::uint8_t {
    if ('a' <= c && c <= 'f') return c - 'a' + 0xa;
    if ('A' <= c && c <= 'F') return c - 'A' + 0xa;
    if ('0' <= c && c <= '9') return c - '0';
    return 0;
}

static auto ParseHexString(std::string_view value) -> ModuleId {
    ModuleId id{};

    for (std::size_t i = 0; i < std::min(value.size() / 2, sizeof(ModuleId)); ++i) {
        id[i] = ParseHexit(value[i * 2 + 1]) | ParseHexit(value[i * 2 + 0]) << 4;
    }

    return id;
}

auto main(std::int32_t argc, const char** argv) -> std::int32_t {
    constexpr auto print_usage = []() -> void {
        std::cout
            << "elf2nro\n"
            << "  Usage:\n"
            << "    elf2nro <options> path_to_elf\n"
            << "\n"
            << "  Basic Options\n"
            << "    --help, -h              print help message\n"
            << "    --output, -o            output filepath\n"
            << "    --id, -i                override module ID\n"
            << "    --header                create dedicated section for NRO header\n";
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
    auto module_id = std::optional<ModuleId>{};
    bool header_section = false;
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
            } else if (name == "id") {
                if (i++ >= args.size() - 1) {
                    std::cerr << "Expected module ID but no arguments remain\n";
                    return 1;
                }
                module_id = ParseHexString(args[i]);
            } else if (name == "header") {
                header_section = true;
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
            } else if (name == "i") {
                if (i++ >= args.size() - 1) {
                    std::cerr << "Expected module ID but no arguments remain\n";
                    return 1;
                }
                module_id = ParseHexString(args[i]);
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

    NXOFile()
        .loadELF(path)
        .setFlag(NXOFile::HeaderSection, header_section)
        .saveNRO(outpath, module_id);

    return 0;
}