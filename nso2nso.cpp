#include "nso.hpp"

#include <cstdint>
#include <iostream>
#include <span>
#include <string>

auto main(std::int32_t argc, const char** argv) -> std::int32_t {
    constexpr auto print_usage = []() -> void {
        std::cout
            << "nso2nso\n"
            << "  Usage:\n"
            << "    nso2nso <options> path_to_nso\n"
            << "\n"
            << "  Basic Options\n"
            << "    --help, -h              print help message\n"
            << "    --output, -o            output filepath\n"
            << "  Compression Options (prefix with `no` to invert)\n"
            << "    --compress-text         compress .text section (default)\n"
            << "    --compress-ro           compress .rodata section (default)\n"
            << "    --compress-data         compress .data section (default)\n"
            << "    --compress, -c          compress all sections (default)\n"
            << "    --zstd, -z              use ZSTD compression for .text\n"
            << "  Verification Options (prefix with `no` to invert)\n"
            << "    --verify-text           verify .text section hash when loading (default)\n"
            << "    --verify-ro             verify .rodata section hash when loading (default)\n"
            << "    --verify-data           verify .data section hash when loading (default)\n"
            << "    --verify, -v            verify all section hashes when loading (default)\n"
            << "  Load Options\n"
            << "    --no-hash-validation    don't validate SHA-256 hashes when loading\n";
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
    bool no_compress_text = false;
    bool no_compress_ro = false;
    bool no_compress_data = false;
    bool no_verify_text = false;
    bool no_verify_ro = false;
    bool no_verify_data = false;
    bool execute_only = false;
    bool use_zstd_for_text = false;
    bool no_validate = false;
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
            } else if (name == "compress-text") {
                no_compress_text = false;
            } else if (name == "no-compress-text") {
                if (use_zstd_for_text) {
                    std::cerr << "[Warning] --no-compress-text option conflicts with previous .text compression option\n";
                }
                no_compress_text = true;
            } else if (name == "compress-ro") {
                no_compress_ro = false;
            } else if (name == "no-compress-ro") {
                no_compress_ro = true;
            } else if (name == "compress-data") {
                no_compress_data = false;
            } else if (name == "no-compress-data") {
                no_compress_data = true;
            } else if (name == "compress") {
                no_compress_text = no_compress_ro = no_compress_data = false;
            } else if (name == "no-compress") {
                if (use_zstd_for_text) {
                    std::cerr << "[Warning] --no-compress-text option conflicts with previous .text compression option\n";
                }
                no_compress_text = no_compress_ro = no_compress_data = true;
            } else if (name == "verify-text") {
                no_verify_text = false;
            } else if (name == "no-verify-text") {
                no_verify_text = true;
            } else if (name == "verify-ro") {
                no_verify_ro = false;
            } else if (name == "no-verify-ro") {
                no_verify_ro = true;
            } else if (name == "verify-data") {
                no_verify_data = false;
            } else if (name == "no-verify-data") {
                no_verify_data = true;
            } else if (name == "verify") {
                no_verify_text = no_verify_ro = no_verify_data = false;
            } else if (name == "no-verify") {
                no_verify_text = no_verify_ro = no_verify_data = true;
            } else if (name == "zstd") {
                if (no_compress_text) {
                    std::cerr << "[WARNING] --zstd option conflicts with previous .text compression option and will be ignored\n";
                } else {
                    use_zstd_for_text = true;
                }
            } else if (name == "help") {
                print_usage();
                return 0;
            } else if (name == "no-hash-validation") {
                no_validate = true;
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
            } else if (name == "c") {
                no_compress_text = no_compress_ro = no_compress_data = false;
            } else if (name == "v") {
                no_verify_text = no_verify_ro = no_verify_data = false;
            } else if (name == "z") {
                if (no_compress_text) {
                    std::cerr << "[WARNING] -z option conflicts with previous .text compression option and will be ignored\n";
                } else {
                    use_zstd_for_text = true;
                }
            } else {
                std::cerr << "[WARNING] Ignoring unknown argument " << arg << "\n";
            }
        } else {
            std::cerr << "[WARNING] Ignoring unknown argument " << arg << "\n";
        }
    }

    NSOFile()
        .loadNSO(path, no_validate)
        .unsetFlag(TextCompress, no_compress_text)
        .unsetFlag(RoCompress, no_compress_ro)
        .unsetFlag(DataCompress, no_compress_data)
        .unsetFlag(TextHash, no_verify_text)
        .unsetFlag(RoHash, no_verify_ro)
        .unsetFlag(DataHash, no_verify_data)
        .setFlag(ExecuteOnlyMemory, execute_only)
        .setFlag(UseZbicCompression, use_zstd_for_text)
        .saveNSO(outpath);

    return 0;
}