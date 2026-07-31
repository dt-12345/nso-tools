#include "elf.h"
#include "lz4.h"
#include "picosha2.h"
#include "zstd.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

enum Flags {
    TextCompress        = 1 << 0,
    RoCompress          = 1 << 1,
    DataCompress        = 1 << 2,
    TextHash            = 1 << 3,
    RoHash              = 1 << 4,
    DataHash            = 1 << 5,
    ExecuteOnlyMemory   = 1 << 6,
    UseZbicCompression  = 1 << 7,
};

enum SectionType : std::uint32_t {
    Section_Text    = 0,
    Section_Ro      = 1,
    Section_Data    = 2,

    Section_Count,
    Section_Start   = Section_Text,
};

static constexpr const char NSO_SIGNATURE[4] = { 'N', 'S', 'O', '0' };

struct Hash {
    std::uint8_t hash[0x20];
};

struct NSOHeader {
    char signature[4];
    std::uint32_t version;
    std::uint32_t reserved0;
    std::uint32_t flags;
    std::uint32_t text_file_offset;
    std::uint32_t text_memory_offset;
    std::uint32_t text_size;
    std::uint32_t module_name_offset;
    std::uint32_t ro_file_offset;
    std::uint32_t ro_memory_offset;
    std::uint32_t ro_size;
    std::uint32_t module_name_size;
    std::uint32_t data_file_offset;
    std::uint32_t data_memory_offset;
    std::uint32_t data_size;
    std::uint32_t bss_size;
    std::uint8_t module_id[0x20];
    std::uint32_t text_compressed_size;
    std::uint32_t ro_compressed_size;
    std::uint32_t data_compressed_size;
    std::uint8_t reserved1[0x24];
    std::uint32_t dyn_str_offset;
    std::uint32_t dyn_str_size;
    std::uint32_t dyn_sym_offset;
    std::uint32_t dyn_sym_size;
    Hash text_hash;
    Hash ro_hash;
    Hash data_hash;
};
static_assert(sizeof(NSOHeader) == 0x100);

auto main(std::int32_t argc, const char** argv) -> std::int32_t {
    constexpr auto print_usage = []() -> void {
        std::cout
            << "elf2nso\n"
            << "  Usage:\n"
            << "    elf2nso <options> path_to_elf\n"
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
            << "    --verify, -v            verify all section hashes when loading (default)\n";
    };

    if (argc < 2) {
        std::cerr << "Too few input arguments\n";
        print_usage();
        return 0;
    }

    const auto path = std::string(argv[argc - 1]);

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

    auto file = std::ifstream(path, std::ios::binary | std::ios::ate);
    const auto file_size = static_cast<std::size_t>(file.tellg());

    if (file_size < sizeof(Elf64_Ehdr)) {
        std::cerr << "Input file is too small to be a valid ELF\n";
        return 1;
    }

    auto file_data = std::vector<std::uint8_t>(file_size);
    file.seekg(0);
    file.read(reinterpret_cast<char*>(file_data.data()), file_data.size());

    const auto elf_hdr = reinterpret_cast<const Elf64_Ehdr*>(file_data.data());
    if (elf_hdr->e_ident[EI_MAG0] != ELFMAG0 || elf_hdr->e_ident[EI_MAG1] != ELFMAG1 || elf_hdr->e_ident[EI_MAG2] != ELFMAG2 || elf_hdr->e_ident[EI_MAG3] != ELFMAG3) {
        std::cerr << "Invalid ELF magic: " << elf_hdr->e_ident << "\n";
        return 1;
    }

    if (elf_hdr->e_type == ET_CORE) {
        std::cerr << "Core dumps are unsupported\n";
        return 1;
    }

    if (elf_hdr->e_machine != EM_AARCH64) {
        std::cerr << "Only AARCH64 is supported\n";
        return 1;
    }

    if (elf_hdr->e_phentsize != sizeof(Elf64_Phdr) || elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
        std::cerr << "Unexpected header size\n";
        return 1;
    }

    const auto phdr_start = elf_hdr->e_phoff;
    const auto phdr_end = phdr_start + elf_hdr->e_phnum * elf_hdr->e_phentsize;
    const auto shdr_start = elf_hdr->e_shoff;
    const auto shdr_end = shdr_start + elf_hdr->e_shnum * elf_hdr->e_shentsize;

    if (phdr_end >= file_data.size() || shdr_start >= file_data.size()) {
        std::cerr << "Program/section header tables are out of range\n";
        return 1;
    }

    NSOHeader header;
    std::memset(std::addressof(header), 0, sizeof(header));
    std::memcpy(header.signature, NSO_SIGNATURE, sizeof(NSO_SIGNATURE));

    std::size_t current_file_offset = sizeof(NSOHeader);
    std::uint32_t current_section = Section_Start;
    auto sections = std::array<std::vector<std::uint8_t>, Section_Count>{};
    auto module_name = std::string_view{};

    auto compress_section_lz4 = [&](std::uint32_t type, const Elf64_Phdr& phdr) -> std::uint32_t {
        const auto req_size = LZ4_compressBound(phdr.p_filesz);
        sections[type].resize(req_size);

        const auto compressed_size = LZ4_compress_default(
            reinterpret_cast<const char*>(file_data.data() + phdr.p_offset),
            reinterpret_cast<char*>(sections[type].data()),
            phdr.p_filesz,
            sections[type].size()
        );

        if (compressed_size <= 0) {
            std::cerr << "LZ4 compression failed\n";
            std::exit(1);
        }

        sections[type].erase(sections[type].begin() + compressed_size, sections[type].end());
        return static_cast<std::uint32_t>(compressed_size);
    };

    auto compress_section_zstd = [&](std::uint32_t type, const Elf64_Phdr& phdr) -> std::uint32_t {
        const auto req_size = ZSTD_compressBound(phdr.p_filesz);
        sections[type].resize(req_size);

        const auto compressed_size = ZSTD_compress(
            sections[type].data(),
            sections[type].size(),
            file_data.data() + phdr.p_offset,
            phdr.p_filesz,
            3
        );

        if (ZSTD_isError(compressed_size)) {
            std::cerr << "ZSTD compression failed: " << ZSTD_getErrorString(ZSTD_getErrorCode(compressed_size)) << "\n";
            std::exit(1);
        }

        sections[type].erase(sections[type].begin() + compressed_size, sections[type].end());
        return static_cast<std::uint32_t>(compressed_size);
    };

    auto get_module_name = [&](std::span<const std::uint8_t> ro_section) -> void {
        if (ro_section.size() < sizeof(std::uint32_t)) {
            std::cerr << "Invalid .rodata section\n";
            std::exit(1);
        }

        std::uint32_t version = 0;
        std::memcpy(std::addressof(version), ro_section.data(), sizeof(version));

        switch (version) {
            case 0: {
                if (ro_section.size() < sizeof(std::uint32_t) + sizeof(std::uint32_t)) {
                    std::cerr << "Invalid .rodata section\n";
                    std::exit(1);
                }

                std::uint32_t name_length = 0;
                std::memcpy(std::addressof(name_length), ro_section.data() + sizeof(std::uint32_t), sizeof(name_length));

                if (ro_section.size() < sizeof(std::uint32_t) + sizeof(std::uint32_t) + name_length) {
                    std::cerr << "Invalid .rodata section\n";
                    std::exit(1);
                }

                module_name = { reinterpret_cast<const char*>(ro_section.data() + sizeof(std::uint32_t) + sizeof(std::uint32_t)), name_length };
                break;
            }
            case 1: {
                struct {
                    std::uint32_t module_header_offset;
                    std::uint32_t sdk_version_offset;
                    std::uint32_t module_name_version;
                    std::uint32_t name_length;
                } info;

                if (ro_section.size() < sizeof(std::uint32_t) + sizeof(info)) {
                    std::cerr << "Invalid .rodata section\n";
                    std::exit(1);
                }

                std::memcpy(std::addressof(info), ro_section.data() + sizeof(std::uint32_t), sizeof(info));

                if (ro_section.size() < sizeof(std::uint32_t) + sizeof(info) + info.name_length) {
                    std::cerr << "Invalid .rodata section\n";
                    std::exit(1);
                }

                module_name = { reinterpret_cast<const char*>(ro_section.data() + sizeof(std::uint32_t) + sizeof(info)), info.name_length };
                break;
            }
            default:
                std::cerr << "Unknown module version " << std::hex << version << "\n";
                std::exit(1);
        }
    };

    std::size_t ro_start = 0, ro_end = 0;
    const auto phdrs = std::span(reinterpret_cast<const Elf64_Phdr*>(file_data.data() + phdr_start), elf_hdr->e_phnum);
    for (const auto& phdr : phdrs) {
        if (current_section >= Section_Count) {
            break;
        }
        
        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        const auto section_start = phdr.p_offset;
        const auto section_end = section_start + phdr.p_filesz;
        if (section_end > file_data.size()) {
            std::cerr << "Program data exceeds file bounds\n";
            return 1;
        }

        const auto raw_data = std::span(file_data.begin() + section_start, file_data.begin() + section_end);
        switch (current_section) {
            case Section_Text:
                header.text_file_offset = current_file_offset;
                header.text_memory_offset = phdr.p_vaddr;
                header.text_size = phdr.p_filesz;

                if (no_compress_text) {
                    current_file_offset += phdr.p_filesz;
                    sections[Section_Text].assign(raw_data.begin(), raw_data.end());
                } else {
                    header.flags |= TextCompress;
                    if (use_zstd_for_text) {
                        const auto compressed_size = compress_section_zstd(Section_Text, phdr);
                        header.text_compressed_size = compressed_size;
                        current_file_offset += compressed_size;
                    } else {
                        const auto compressed_size = compress_section_lz4(Section_Text, phdr);
                        header.text_compressed_size = compressed_size;
                        current_file_offset += compressed_size;
                    }
                }

                if (!no_verify_text) {
                    header.flags |= TextHash;
                    picosha2::hash256(raw_data, header.text_hash.hash, header.text_hash.hash + sizeof(header.text_hash.hash));
                }

                if (execute_only) {
                    header.flags |= ExecuteOnlyMemory;
                }

                break;
            case Section_Ro:
                header.ro_file_offset = current_file_offset;
                header.ro_memory_offset = phdr.p_vaddr;
                header.ro_size = phdr.p_filesz;

                if (no_compress_ro) {
                    current_file_offset += phdr.p_filesz;
                    sections[Section_Ro].assign(raw_data.begin(), raw_data.end());
                } else {
                    header.flags |= RoCompress;
                    const auto compressed_size = compress_section_lz4(Section_Ro, phdr);
                    header.ro_compressed_size = compressed_size;
                    current_file_offset += compressed_size;
                }

                if (!no_verify_ro) {
                    header.flags |= RoHash;
                    picosha2::hash256(raw_data, header.ro_hash.hash, header.ro_hash.hash + sizeof(header.ro_hash.hash));
                }

                ro_start = section_start;
                ro_end = section_end;

                get_module_name(raw_data);
                break;
            case Section_Data:
                header.data_file_offset = current_file_offset;
                header.data_memory_offset = phdr.p_vaddr;
                header.data_size = phdr.p_filesz;

                if (no_compress_data) {
                    current_file_offset += phdr.p_filesz;
                    sections[Section_Data].assign(raw_data.begin(), raw_data.end());
                } else {
                    header.flags |= DataCompress;
                    const auto compressed_size = compress_section_lz4(Section_Data, phdr);
                    header.data_compressed_size = compressed_size;
                    current_file_offset += compressed_size;
                }

                if (!no_verify_data) {
                    header.flags |= DataHash;
                    picosha2::hash256(raw_data, header.data_hash.hash, header.data_hash.hash + sizeof(header.data_hash.hash));
                }

                if (phdr.p_memsz > phdr.p_filesz) {
                    header.bss_size = phdr.p_memsz - phdr.p_filesz;
                }

                break;
        }

        ++current_section;
    }

    // push everything back to make room for the module name (we could put this at the end, but official NSOs put it first)
    header.text_file_offset += module_name.size() + 1;
    header.ro_file_offset += module_name.size() + 1;
    header.data_file_offset += module_name.size() + 1;
    header.module_name_offset = sizeof(header);
    header.module_name_size = module_name.size() + 1;

    bool found_note = false, found_dynsym = false, found_dynstr = false;
    const auto shdrs = std::span(reinterpret_cast<const Elf64_Shdr*>(file_data.data() + shdr_start), elf_hdr->e_shnum);
    for (const auto& shdr : shdrs) {
        if (found_note && found_dynsym && found_dynstr) {
            break;
        }

        const auto section_start = shdr.sh_offset;
        const auto section_end = section_start + shdr.sh_size;
        if (section_end > file_data.size()) {
            std::cerr << "Section data exceeds file bounds\n";
            return 1;
        }

        switch (shdr.sh_type) {
            case SHT_DYNSYM: {
                if (section_start >= ro_start && section_end <= ro_end) {
                    header.dyn_sym_offset = section_start - ro_start;
                    header.dyn_sym_size = section_end - section_start;
                    found_dynsym = true;
                }
                break;
            }
            case SHT_STRTAB: { // check string table to make sure this is .dynstr and not another string table
                if (section_start >= ro_start && section_end <= ro_end) {
                    header.dyn_str_offset = section_start - ro_start;
                    header.dyn_str_size = section_end - section_start;
                    found_dynstr = true;
                }
                break;
            }
            case SHT_NOTE: {
                const auto raw_data = std::span(file_data.begin() + section_start, file_data.begin() + section_end);
                if (raw_data.size() < sizeof(Elf64_Nhdr)) {
                    std::cerr << raw_data.size() << " Invalid note section\n";
                    return 1;
                }

                const auto nhdr = reinterpret_cast<const Elf64_Nhdr*>(raw_data.data());
                if (nhdr->n_type != NT_GNU_BUILD_ID || nhdr->n_namesz != 4 || nhdr->n_descsz > sizeof(header.module_id)) {
                    continue;
                }

                if (raw_data.size() < sizeof(Elf64_Nhdr) + nhdr->n_namesz + nhdr->n_descsz) {
                    std::cerr << "Invalid note section\n";
                    return 1;
                }

                const auto name = std::string_view{ reinterpret_cast<const char*>(raw_data.data() + sizeof(Elf64_Nhdr)), nhdr->n_namesz };
                if (name[0] != 'G' || name[1] != 'N' || name[2] != 'U' || name[3] != '\0') {
                    continue;
                }

                std::memcpy(header.module_id, raw_data.data() + sizeof(Elf64_Nhdr) + nhdr->n_namesz, nhdr->n_descsz);
                found_note = true;
                break;
            }
        }
    }

    if (outpath.empty()) {
        outpath = module_name;
    }

    auto outfile = std::ofstream(std::string(outpath), std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(std::addressof(header)), sizeof(header));

    outfile.write(module_name.data(), module_name.size());
    outfile.put('\0');

    for (const auto& section : sections) {
        outfile.write(reinterpret_cast<const char*>(section.data()), section.size());
    }

    return 0;
}