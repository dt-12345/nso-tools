#include "nso.hpp"

#include "lz4.h"
#include "picosha2.h"
#include "zstd.h"

#include "elf.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

template <typename... Ts>
[[noreturn]] static auto Panic(Ts&&... args) -> void {
    (std::cerr << ... << std::forward<Ts>(args)) << "\n";
    std::exit(1);
}

static constexpr const char cGNUNoteMagic[] = { 'G', 'N', 'U', '\0' };

static auto ReadFile(std::string_view path) -> std::vector<std::uint8_t> {
    auto file = std::ifstream(std::string(path), std::ios::binary | std::ios::ate);
    if (!file) {
        Panic("Failed to open ", path);
    }

    const auto size = file.tellg();
    file.seekg(0);

    auto data = std::vector<std::uint8_t>(size);
    file.read(reinterpret_cast<char*>(data.data()), data.size());

    return data;
}

static auto GetSpan(const std::vector<std::uint8_t>& file_data, std::size_t start, std::size_t size, const char* name) -> std::span<const std::uint8_t> {
    if (start > file_data.size() || start + size > file_data.size()) {
        Panic(name, " is out of range of the file");
    }

    return { file_data.begin() + start, file_data.begin() + start + size };
}

static auto DecompressLZ4(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) -> void {
    const auto result = LZ4_decompress_safe(
        reinterpret_cast<const char*>(src.data()),
        reinterpret_cast<char*>(dst.data()),
        src.size(),
        dst.size()
    );

    if (result < dst.size()) {
        Panic("LZ4 decompression failed");
    }
}

static auto DecompressZstd(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) -> void {
    const auto result = ZSTD_decompress(
        dst.data(),
        dst.size(),
        src.data(),
        src.size()
    );

    if (ZSTD_isError(result) || result < dst.size()) {
        Panic("ZSTD decompression failed");
    }
}

static auto CompressLZ4(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) -> std::uint32_t {
    const auto req_size = LZ4_compressBound(src.size());
    dst.resize(req_size);

    const auto compressed_size = LZ4_compress_default(
        reinterpret_cast<const char*>(src.data()),
        reinterpret_cast<char*>(dst.data()),
        src.size(),
        dst.size()
    );

    if (compressed_size <= 0) {
        Panic("LZ4 compression failed");
    }

    dst.erase(dst.begin() + compressed_size, dst.end());
    return static_cast<std::uint32_t>(compressed_size);
};

static auto CompressZstd(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) -> std::uint32_t {
    const auto req_size = ZSTD_compressBound(src.size());
    dst.resize(req_size);

    const auto compressed_size = ZSTD_compress(
        dst.data(),
        dst.size(),
        src.data(),
        src.size(),
        3
    );

    if (ZSTD_isError(compressed_size)) {
        Panic("ZSTD compression failed: ", ZSTD_getErrorString(ZSTD_getErrorCode(compressed_size)));
    }

    dst.erase(dst.begin() + compressed_size, dst.end());
    return static_cast<std::uint32_t>(compressed_size);
};

static constexpr std::string_view cSectionNames[] = { ".text", ".rodata", ".data" };

auto NSOFile::loadNSO(std::string_view path, bool skip_validation) -> NSOFile& {
    const auto file_data = ReadFile(path);

    if (file_data.size() < sizeof(NSOHeader)) {
        Panic("Input file is too small to be a valid NSO file");
    }

    const auto header = reinterpret_cast<const NSOHeader*>(file_data.data());

    if (std::memcmp(header->signature, NSO_SIGNATURE, sizeof(NSO_SIGNATURE)) != 0) {
        Panic("Invalid NSO signature");
    }

    if (header->version != 0) {
        Panic("Invalid NSO version");
    }

    mFlags = header->flags;
    mBssSize = header->bss_size;

    for (std::uint32_t section = Section_Start; section < Section_Count; ++section) {
        bool verify = false;
        switch (section) {
            case Section_Text:
                if (isFlagSet(TextCompress)) {
                    const auto section_data = GetSpan(file_data, header->text_file_offset, header->text_compressed_size, ".text");
                    auto decompressed = std::vector<std::uint8_t>(header->text_size);
                    if (isFlagSet(UseZbicCompression)) {
                        DecompressZstd(decompressed, section_data);
                    } else {
                        DecompressLZ4(decompressed, section_data);
                    }
                    setSection(Section_Text, decompressed);
                } else {
                    setSection(Section_Text, GetSpan(file_data, header->text_file_offset, header->text_size, ".text"));
                }

                verify = isFlagSet(TextHash);
                break;
            case Section_Ro:
                if (isFlagSet(RoCompress)) {
                    const auto section_data = GetSpan(file_data, header->ro_file_offset, header->ro_compressed_size, ".rodata");
                    auto decompressed = std::vector<std::uint8_t>(header->ro_size);
                    DecompressLZ4(decompressed, section_data);
                    setSection(Section_Ro, decompressed);
                } else {
                    setSection(Section_Ro, GetSpan(file_data, header->ro_file_offset, header->ro_size, ".rodata"));
                }

                verify = isFlagSet(RoHash);
                break;
            case Section_Data:
                if (isFlagSet(DataCompress)) {
                    const auto section_data = GetSpan(file_data, header->data_file_offset, header->data_compressed_size, ".data");
                    auto decompressed = std::vector<std::uint8_t>(header->data_size);
                    DecompressLZ4(decompressed, section_data);
                    setSection(Section_Data, decompressed);
                } else {
                    setSection(Section_Data, GetSpan(file_data, header->data_file_offset, header->data_size, ".data"));
                }

                verify = isFlagSet(DataHash);
                break;
        }

        if (verify && !skip_validation) {
            std::array<std::uint8_t, picosha2::k_digest_size> hash;
            picosha2::hash256(getSection(section), hash);
            if (std::memcmp(hash.data(), header->section_hashes[section].data(), hash.size()) != 0) {
                Panic("Hash mismatch for ", cSectionNames[section]);
            }
        }
    }

    const auto dynamic = getDynamic();
    if (header->dyn_str_size == 0) {
        mDynStr = findDynStrRange(dynamic).value_or({});
    } else {
        mDynStr.start = header->dyn_str_offset + getRodataOffset();
        mDynStr.size = header->dyn_str_size;
    }

    if (header->dyn_sym_size == 0) {
        mDynSym = findDynSymRange(dynamic).value_or({});
    } else {
        mDynSym.start = header->dyn_sym_offset + getRodataOffset();
        mDynSym.size = header->dyn_sym_size;
    }

    setModuleIdFromRodata();
    setModuleNameFromRodata();

    return *this;
}

auto NSOFile::loadELF(std::string_view path) -> NSOFile& {
    const auto file_data = ReadFile(path);

    if (file_data.size() < sizeof(Elf64_Ehdr)) {
        Panic("Input file is too small to be a valid ELF file");
    }

    const auto elf_hdr = reinterpret_cast<const Elf64_Ehdr*>(file_data.data());
    if (elf_hdr->e_ident[EI_MAG0] != ELFMAG0 || elf_hdr->e_ident[EI_MAG1] != ELFMAG1 || elf_hdr->e_ident[EI_MAG2] != ELFMAG2 || elf_hdr->e_ident[EI_MAG3] != ELFMAG3) {
        Panic("Invalid ELF magic: ", elf_hdr->e_ident);
    }

    if (elf_hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        Panic("Only 64-bit executables are supported");
    }

    if (elf_hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        Panic("Only LE executables are supported");
    }

    if (elf_hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        Panic("Invalid ELF version");
    }

    if (elf_hdr->e_type == ET_CORE) {
        Panic("Core dumps are unsupported");
    }

    if (elf_hdr->e_machine != EM_AARCH64) {
        Panic("Only AARCH64 is supported");
    }

    if (elf_hdr->e_phentsize != sizeof(Elf64_Phdr) || elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
        Panic("Unexpected header size");
    }

    const auto phdr_start = elf_hdr->e_phoff;
    const auto phdr_end = phdr_start + elf_hdr->e_phnum * elf_hdr->e_phentsize;
    const auto shdr_start = elf_hdr->e_shoff;
    const auto shdr_end = shdr_start + elf_hdr->e_shnum * elf_hdr->e_shentsize;

    if (phdr_end > file_data.size() || shdr_end > file_data.size()) {
        Panic("Program/section header tables are out of range");
    }

    std::uint32_t current_section = 0;
    std::size_t ro_start = 0, ro_end = 0;
    const auto phdrs = std::span(reinterpret_cast<const Elf64_Phdr*>(file_data.data() + phdr_start), elf_hdr->e_phnum);
    for (const auto& phdr : phdrs) {
        if (current_section >= Section_Count) {
            break;
        }
        
        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        const auto section_data = GetSpan(file_data, phdr.p_offset, phdr.p_filesz, "Program");
        setSection(current_section, section_data);

        switch (current_section) {
            case Section_Text:
                if ((phdr.p_flags & PF_X) == 0) {
                    Panic(".text segment is not executable");
                }
                if ((phdr.p_flags & PF_W) != 0) {
                    Panic(".text segment is writable");
                }
                if ((phdr.p_flags & PF_R) == 0) {
                    setFlag(ExecuteOnlyMemory);
                }
                break;
            case Section_Ro:
                if (phdr.p_flags != PF_R) {
                    Panic(".rodata segment is not read-only");
                }
                ro_start = phdr.p_offset;
                ro_end = phdr.p_offset + phdr.p_filesz;
                break;
            case Section_Data:
                if (phdr.p_flags != (PF_R | PF_W)) {
                    Panic(".data segment is not read-write");
                }
                if (phdr.p_memsz > phdr.p_filesz) {
                    setBssSize(phdr.p_memsz - phdr.p_filesz);
                }
                break;
        }

        ++current_section;
    }

    bool found_note = false, found_dynsym = false, found_dynstr = false;
    const auto shdrs = std::span(reinterpret_cast<const Elf64_Shdr*>(file_data.data() + shdr_start), elf_hdr->e_shnum);

    const auto string_table_index = elf_hdr->e_shstrndx;
    if (string_table_index >= shdrs.size()) {
        Panic("Invalid section string table index");
    }

    const auto& string_table_header = shdrs[string_table_index];
    const auto string_table_start = string_table_header.sh_offset;
    const auto string_table_end = string_table_start + string_table_header.sh_size;
    if (string_table_end > file_data.size()) {
        Panic("Section string table data exceeds file bounds");
    }

    const auto string_table = std::span(reinterpret_cast<const char*>(file_data.data() + string_table_start), string_table_header.sh_size);
    for (const auto& shdr : shdrs) {
        if (found_note && found_dynsym && found_dynstr) {
            break;
        }

        const auto section_start = shdr.sh_offset;
        const auto section_end = section_start + shdr.sh_size;
        if (section_end > file_data.size()) {
            Panic("Section data exceeds file bounds");
        }

        switch (shdr.sh_type) {
            case SHT_DYNSYM: {
                if (section_start >= ro_start && section_end <= ro_end) {
                    mDynSym.start = getRodataOffset() + (section_start - ro_start);
                    mDynSym.size = section_end - section_start;
                    found_dynsym = true;
                }
                break;
            }
            case SHT_STRTAB: {
                if (shdr.sh_name >= string_table.size()) {
                    Panic("Invalid section name offset");
                }
                const auto name = string_table.data() + shdr.sh_name;
                const auto max_size = std::min(string_table.size() - shdr.sh_name, std::strlen(".dynstr"));
                if (std::strncmp(name, ".dynstr", max_size) == 0) {
                    if (section_start >= ro_start && section_end <= ro_end) {
                        mDynStr.start = getRodataOffset() + (section_start - ro_start);
                        mDynStr.size = section_end - section_start;
                        found_dynstr = true;
                    }
                }
                break;
            }
            case SHT_NOTE: {
                const auto raw_data = std::span(file_data.begin() + section_start, file_data.begin() + section_end);
                if (raw_data.size() < sizeof(Elf64_Nhdr)) {
                    Panic("Note section is too small to fit header");
                }

                const auto nhdr = reinterpret_cast<const Elf64_Nhdr*>(raw_data.data());
                if (nhdr->n_type != NT_GNU_BUILD_ID || nhdr->n_namesz != 4 || nhdr->n_descsz > sizeof(ModuleId)) {
                    continue;
                }

                if (raw_data.size() < sizeof(Elf64_Nhdr) + nhdr->n_namesz + nhdr->n_descsz) {
                    Panic("Note section is too small to fit name and description");
                }

                const auto name = std::string_view{ reinterpret_cast<const char*>(raw_data.data() + sizeof(Elf64_Nhdr)), nhdr->n_namesz };
                if (std::memcmp(name.data(), cGNUNoteMagic, sizeof(cGNUNoteMagic)) != 0) {
                    continue;
                }

                std::memcpy(mModuleId.data(), raw_data.data() + sizeof(Elf64_Nhdr) + nhdr->n_namesz, nhdr->n_descsz);
                found_note = true;
                break;
            }
        }
    }

    if (!found_note) {
        setModuleIdFromRodata();
    }
    setModuleNameFromRodata();

    return *this;
}

auto NSOFile::saveNSO(std::string_view path, const std::optional<std::string_view>& name, const std::optional<ModuleId>& module_id) -> NSOFile& {
    if (name) {
        setName(*name);
    }

    if (module_id) {
        setModuleId(*module_id);
    }

    NSOHeader header;
    std::memset(std::addressof(header), 0, sizeof(header));
    std::memcpy(header.signature, NSO_SIGNATURE, sizeof(NSO_SIGNATURE));

    header.flags = mFlags;
    header.bss_size = getBssSize();
    std::memcpy(header.module_id.data(), mModuleId.data(), mModuleId.size());
    header.dyn_str_offset = mDynStr.start != 0 ? mDynStr.start - getRodataOffset() : 0;
    header.dyn_str_size = mDynStr.size;
    header.dyn_sym_offset = mDynSym.start != 0 ? mDynSym.start - getRodataOffset() : 0;
    header.dyn_sym_size = mDynSym.size;

    if (path.empty()) {
        path = mName;
    }

    auto file = std::ofstream(std::string(path), std::ios::binary);
    if (!file) {
        Panic("Failed to open ", path);
    }

    file.seekp(sizeof(NSOHeader));
    std::uint32_t current_file_offset = file.tellp();

    header.module_name_offset = current_file_offset;
    header.module_name_size = mName.size() + 1;
    file.write(mName.data(), mName.size());
    file.put('\0');

    current_file_offset = file.tellp();

    std::uint32_t memory_offset = 0;
    for (std::uint32_t section = Section_Start; section < Section_Count; ++section) {
        bool verify = false;
        const auto& section_data = getSection(section);
        switch (section) {
            case Section_Text:
                header.text_file_offset = current_file_offset;
                header.text_memory_offset = memory_offset;
                header.text_size = section_data.size();
                if (isFlagSet(TextCompress)) {
                    auto compressed = std::vector<std::uint8_t>{};
                    if (isFlagSet(UseZbicCompression)) {
                        header.text_compressed_size = CompressZstd(compressed, section_data);
                    } else {
                        header.text_compressed_size = CompressLZ4(compressed, section_data);
                    }
                    file.write(reinterpret_cast<const char*>(compressed.data()), compressed.size());
                } else {
                    file.write(reinterpret_cast<const char*>(section_data.data()), section_data.size());
                }
                verify = isFlagSet(TextHash);
                break;
            case Section_Ro:
                header.ro_file_offset = current_file_offset;
                header.ro_memory_offset = memory_offset;
                header.ro_size = section_data.size();
                if (isFlagSet(RoCompress)) {
                    auto compressed = std::vector<std::uint8_t>{};
                    header.ro_compressed_size = CompressLZ4(compressed, section_data);
                    file.write(reinterpret_cast<const char*>(compressed.data()), compressed.size());
                } else {
                    file.write(reinterpret_cast<const char*>(section_data.data()), section_data.size());
                }
                verify = isFlagSet(RoHash);
                break;
            case Section_Data:
                header.data_file_offset = current_file_offset;
                header.data_memory_offset = memory_offset;
                header.data_size = section_data.size();
                if (isFlagSet(DataCompress)) {
                    auto compressed = std::vector<std::uint8_t>{};
                    header.data_compressed_size = CompressLZ4(compressed, section_data);
                    file.write(reinterpret_cast<const char*>(compressed.data()), compressed.size());
                } else {
                    file.write(reinterpret_cast<const char*>(section_data.data()), section_data.size());
                }
                verify = isFlagSet(DataHash);
                break;
        }

        if (verify) {
            picosha2::hash256(getSection(section), header.section_hashes[section]);
        }

        current_file_offset = file.tellp();
        memory_offset += (section_data.size() + cSectionAlignment - 1) / cSectionAlignment * cSectionAlignment;
    }

    file.seekp(0);
    file.write(reinterpret_cast<const char*>(std::addressof(header)), sizeof(header));

    return *this;
}

auto NSOFile::getRocrtInit() const -> const RocrtInit* {
    const auto& text = getText();
    if (text.size() < cMinimumRocrtInitSize) {
        Panic("Invalid .text section");
    }

    return reinterpret_cast<const RocrtInit*>(text.data());
}

auto NSOFile::getModuleHeader(std::size_t* offset) const -> const ModuleHeader* {
    const auto& text = getText();
    const auto& rodata = getRodata();

    const auto rocrt_init = getRocrtInit();
    if (isInText(rocrt_init->rocrt_info_offset, cMinimumRocrtInitSize)) {
        const auto text_offset = rocrt_init->rocrt_info_offset - getTextOffset();
        *offset = rocrt_init->rocrt_info_offset;
        return reinterpret_cast<const ModuleHeader*>(text.data() + text_offset);
    } else if (isInRodata(rocrt_init->rocrt_info_offset, cMinimumModuleHeaderSize)) {
        const auto rodata_offset = rocrt_init->rocrt_info_offset - getRodataOffset();
        *offset = rocrt_init->rocrt_info_offset;
        return reinterpret_cast<const ModuleHeader*>(rodata.data() + rodata_offset);
    } else {
        Panic(".rocrt.info must be in .text or .rodata");
    }
}

auto NSOFile::getDynamic() const -> std::span<const Elf64_Dyn> {
    const auto dyn_range = findDynamicRange();
    if (!dyn_range) {
        Panic("Failed to find .dynamic");
    }

    if (!isInData(dyn_range->start, dyn_range->size)) {
        Panic(".dynamic must be in .data");
    }

    return std::span(reinterpret_cast<const Elf64_Dyn*>(getData().data() + dyn_range->start - getDataOffset()), dyn_range->size / sizeof(Elf64_Dyn));
}

auto NSOFile::findDynamicRange() const -> std::optional<Range> {
    const auto& data = getData();

    std::size_t header_offset = 0;
    const auto module_header = getModuleHeader(std::addressof(header_offset));

    if (!isInData(header_offset + module_header->dynamic_offset)) {
        Panic(".dynamic must be in .data");
    }

    const auto data_offset = header_offset + module_header->dynamic_offset - getDataOffset();
    auto dyn = reinterpret_cast<const Elf64_Dyn*>(data.data() + data_offset);
    std::size_t count = 0;
    while (dyn[count].d_tag != DT_NULL) {
        if (data_offset + ++count * sizeof(Elf64_Dyn) >= data.size()) {
            Panic("No DT_NULL found in .dynamic before end of data");
        }
    }

    return std::make_optional<Range>(header_offset + module_header->dynamic_offset, (count + 1) * sizeof(Elf64_Dyn));
}

auto NSOFile::findDynSymRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range> {
    const auto& rodata = getRodata();

    auto range = Range{};

    bool found_start = false;
    bool found_size = false;
    for (const auto& dyn : dynamic) {
        if (dyn.d_tag == DT_SYMTAB) {
            if (!isInRodata(dyn.d_un.d_ptr)) {
                Panic(".dynsym must be in .rodata");
            }
            range.start = dyn.d_un.d_ptr;
            found_start = true;
        } else if (dyn.d_tag == DT_HASH) {
            if (!isInRodata(dyn.d_un.d_ptr, sizeof(ElfHashTable))) {
                Panic(".hash must be in .rodata");
            }

            const auto offset = dyn.d_un.d_ptr - getRodataOffset();
            const auto nchain = reinterpret_cast<const ElfHashTable*>(rodata.data() + offset)->nchain;
            range.size = nchain * sizeof(Elf64_Sym);
            found_size = true;
        } else if (dyn.d_tag == DT_GNU_HASH) {
            if (!isInRodata(dyn.d_un.d_ptr, sizeof(GnuHashTable))) {
                Panic(".gnu.hash must be in .rodata");
            }

            const auto offset = dyn.d_un.d_ptr - getRodataOffset();
            const auto hash_table = reinterpret_cast<const GnuHashTable*>(rodata.data() + offset);
            const auto nbuckets = hash_table->nbucket;
            const auto sym_offset = hash_table->sym_offset;

            const auto bucket_offset = offset + 0x10 + hash_table->bloom_size * sizeof(std::uint64_t);
            const auto bucket_end_offset = bucket_offset + sizeof(std::uint32_t) * nbuckets;
            if (bucket_end_offset > rodata.size()) {
                Panic(".gnu.hash does not fit in .rodata");
            }

            std::uint32_t sym_index = 0;
            for (const auto bucket : std::span(reinterpret_cast<const std::uint32_t*>(rodata.data() + bucket_offset), nbuckets)) {
                sym_index = std::max(bucket, sym_index);
            }

            std::uint32_t sym_count;
            if (sym_index < sym_offset) {
                sym_count = sym_offset;
            } else {
                while (bucket_end_offset + sym_index * sizeof(std::uint32_t) < rodata.size()) {
                    const auto hash_value = *reinterpret_cast<const std::uint32_t*>(rodata.data() + bucket_end_offset + sym_index * sizeof(std::uint32_t));
                    if (hash_value & 1) {
                        break;
                    } else {
                        ++sym_index;
                    }
                }
                sym_count = sym_index + 1;
            }

            range.size = sym_count * sizeof(Elf64_Sym);
            found_size = true;
        }

        if (found_start && found_size) {
            break;
        }
    }

    if (found_start && found_size) {
        if (!isInRodata(range.start, range.size)) {
            Panic(".dynsym does not fit in .rodata");
        }
        return std::make_optional(std::move(range));
    } else {
        return std::nullopt;
    }
}

auto NSOFile::findDynStrRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range> {
    auto range = Range{};

    bool found_start = false;
    bool found_size = false;
    for (const auto& dyn : dynamic) {
        if (dyn.d_tag == DT_STRTAB) {
            if (dyn.d_un.d_ptr < getRodataOffset()) {
                Panic(".dynsym must be in .rodata");
            }
            range.start = dyn.d_un.d_ptr;
            found_start = true;
        } else if (dyn.d_tag == DT_STRSZ) {
            range.size = dyn.d_un.d_val;
            found_size = true;
        }

        if (found_start && found_size) {
            break;
        }
    }

    if (found_start && found_size) {
        if (!isInRodata(range.start, range.size)) {
            Panic(".dynstr does not fit in .rodata");
        }
        return std::make_optional(std::move(range));
    } else {
        return std::nullopt;
    }
}

auto NSOFile::findModuleNameRange() const -> std::optional<Range> {
    std::size_t header_offset = 0;
    const auto module_header = getModuleHeader(std::addressof(header_offset));

    if (GetRocrtVersion(getRocrtInit()) == 0) {
        const auto& rodata = getRodata();

        if (rodata.size() < sizeof(NxDebuglink)) {
            return std::nullopt;
        }

        const auto header = reinterpret_cast<const NxDebuglink*>(rodata.data());
        if (header->version != 0) {
            Panic("Invalid .nx_debuglink section");
        }

        if (rodata.size() < sizeof(NxDebuglink) + header->name_size) {
            Panic(".nx_debuglink does not fit in .rodata");
        }

        return std::make_optional<Range>(getRodataOffset(), sizeof(NxDebuglink) + header->name_size);
    } else {
        const auto start = header_offset + module_header->nx_debuglink_start;
        const auto end = header_offset + module_header->nx_debuglink_end;
        if (end < start || end - start < sizeof(NxDebuglink)) {
            Panic("Invalid .nx_debuglink range in module header");
        }
        if (!isInRodata(start, end - start)) {
            Panic(".nx_debuglink must be in .rodata");
        }
        return std::make_optional<Range>(start, end - start);
    }
}

auto NSOFile::findModuleIdRange() const -> std::optional<Range> {
    std::size_t header_offset = 0;
    const auto module_header = getModuleHeader(std::addressof(header_offset));

    if (GetRocrtVersion(getRocrtInit()) == 0) {
        const auto& rodata = getRodata();

        std::size_t current_offset = (rodata.size() > 0x2000 ? rodata.size() - 0x2000 : 0) / alignof(Elf64_Nhdr) * alignof(Elf64_Nhdr);

        while (current_offset + sizeof(cGNUNoteMagic) < rodata.size()) {
            if (std::memcmp(rodata.data() + current_offset, cGNUNoteMagic, sizeof(cGNUNoteMagic)) == 0) {
                const auto note_header_end = rodata.data() + current_offset;
                if (current_offset >= sizeof(Elf64_Nhdr)) {
                    const auto note_header = reinterpret_cast<const Elf64_Nhdr*>(rodata.data() + current_offset - sizeof(Elf64_Nhdr));
                    if (note_header->n_namesz == 4 && (note_header->n_type == 3 || note_header->n_type == 4) && note_header->n_descsz <= sizeof(ModuleId)) {
                        if (current_offset + note_header->n_namesz + note_header->n_descsz <= rodata.size()) {
                            return std::make_optional<Range>(
                                getRodataOffset() + current_offset - sizeof(Elf64_Nhdr),
                                sizeof(Elf64_Nhdr) + note_header->n_namesz + note_header->n_descsz
                            );
                        }
                    }
                }
            }
            current_offset += sizeof(cGNUNoteMagic);
        }

        return std::nullopt;
    } else {
        const auto start = header_offset + module_header->gnu_buildid_start;
        const auto end = header_offset + module_header->gnu_buildid_end;
        if (end < start || end - start < sizeof(Elf64_Nhdr)) {
            Panic("Invalid .note.gnu.build-id range in module header");
        }
        if (!isInRodata(start, end - start)) {
            Panic(".note.gnu.build-id must be in .rodata");
        }
        return std::make_optional<Range>(start, end - start);
    }
}

auto NSOFile::setModuleId(const ModuleId& id) -> NSOFile& {
    const auto range = findModuleIdRange();
    if (!range) {
        Panic("No module id in file");
    }

    if (!isInRodata(range->start, range->size)) {
        Panic(".note.gnu.build-id must be in .rodata");
    }

    if (range->size < sizeof(Elf64_Nhdr)) {
        Panic("Module id range is too small");
    }

    const auto header = reinterpret_cast<const Elf64_Nhdr*>(getRodata().data() + range->start - getRodataOffset());
    const auto id_size = header->n_descsz;
    if (id_size > sizeof(ModuleId)) {
        Panic("Invalid module id size");
    }

    if (range->size < sizeof(Elf64_Nhdr) + header->n_namesz + header->n_descsz) {
        Panic("Module id range is too small");
    }

    std::memcpy(mModuleId.data(), id.data(), id_size);
    std::memcpy(getRodata().data() + range->start + sizeof(Elf64_Nhdr) + header->n_namesz - getRodataOffset(), id.data(), id_size);

    return *this;
}

auto NSOFile::setModuleNameFromRodata() -> void {
    const auto module_name_range = findModuleNameRange();
    if (!module_name_range) {
        Panic("Module name not found");
    }

    if (!isInRodata(module_name_range->start, module_name_range->size)) {
        Panic(".nx_debuglink must be in .rodata");
    }

    if (module_name_range->size < sizeof(NxDebuglink)) {
        Panic("Module name range is too small to be valid");
    }

    const auto& rodata = getRodata();
    const auto rodata_offset = module_name_range->start - getRodataOffset();

    const auto nx_debuglink = reinterpret_cast<const NxDebuglink*>(rodata.data() + rodata_offset);
    if (nx_debuglink->version != 0 || nx_debuglink->name_size == 0) {
        Panic("Invalid .nx_debuglink section");
    }

    if (module_name_range->size < sizeof(NxDebuglink) + nx_debuglink->name_size) {
        Panic("Module name range is too small to be valid");
    }

    mName = { reinterpret_cast<const char*>(rodata.data() + rodata_offset + sizeof(NxDebuglink)), nx_debuglink->name_size };

    if (mName.ends_with(".nss")) {
        mName = mName.substr(0, mName.size() - 4);
    }

    if (const auto pos = mName.find_last_of("/\\")) {
        mName = mName.substr(pos + 1);
    }
}

auto NSOFile::setModuleIdFromRodata() -> void {
    const auto module_id_range = findModuleIdRange();
    if (!module_id_range) {
        Panic("No module id found");
    }

    if (!isInRodata( module_id_range->start,  module_id_range->size)) {
        Panic(".note.gnu.build-id must be in .rodata");
    }

    if (module_id_range->size < sizeof(Elf64_Nhdr)) {
        Panic("Module id range is too small to be valid");
    }

    const auto& rodata = getRodata();
    const auto rodata_offset = module_id_range->start - getRodataOffset();

    const auto note_header = reinterpret_cast<const Elf64_Nhdr*>(rodata.data() + rodata_offset);
    if ((note_header->n_type != 3 && note_header->n_type != 4) || note_header->n_namesz != 4 || note_header->n_descsz > sizeof(ModuleId)) {
        Panic("Unsupported .note.gnu.build-id format");
    }

    if (module_id_range->size < sizeof(Elf64_Nhdr) + note_header->n_namesz + note_header->n_descsz) {
        Panic("Module id range is too small to be valid");
    }

    if (std::memcmp(reinterpret_cast<const Elf64_Nhdr*>(rodata.data() + rodata_offset + sizeof(Elf64_Nhdr)), cGNUNoteMagic, sizeof(cGNUNoteMagic)) != 0) {
        Panic("Invalid .note.gnu.build-id magic");
    }

    std::memcpy(
        mModuleId.data(),
        reinterpret_cast<const Elf64_Nhdr*>(rodata.data() + rodata_offset + sizeof(Elf64_Nhdr) + note_header->n_namesz),
        note_header->n_descsz
    );
}