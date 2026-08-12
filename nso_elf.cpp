#include "nso.hpp"

#include "elf.h"

#include <climits>
#include <limits>
#include <iostream>
#include <fstream>
#include <unordered_set>

template <typename... Ts>
[[noreturn]] static auto Panic(Ts&&... args) -> void {
    (std::cerr << ... << std::forward<Ts>(args)) << "\n";
    std::exit(1);
}

enum Encoding : std::uint8_t {
    DW_EH_PE_uleb128    = 0x01,
    DW_EH_PE_udata2     = 0x02,
    DW_EH_PE_udata4     = 0x03,
    DW_EH_PE_udata8     = 0x04,
    DW_EH_PE_sleb128    = 0x09,
    DW_EH_PE_sdata2     = 0x0a,
    DW_EH_PE_sdata4     = 0x0b,
    DW_EH_PE_sdata8     = 0x0c,

    DW_EH_PE_absptr     = 0x00,
    DW_EH_PE_pcrel      = 0x10,
    DW_EH_PE_textrel    = 0x20, // unsupported
    DW_EH_PE_datarel    = 0x30,
    DW_EH_PE_funcrel    = 0x40, // unsupported
    DW_EH_PE_aligned    = 0x50, // unsupported

    DW_EH_PE_indirect   = 0x80,

    DW_EH_PE_omit       = 0xff,

    TypeMask            = 0x0f,
    SizeMask            = 0x07,
    IsSignedMask        = 0x08,
    ApplyTypeMask       = 0xf0,
};

struct EhFrameHdr {
    std::uint8_t version;
    Encoding eh_frame_ptr_enc;
    Encoding fde_count_enc;
    Encoding table_enc;
};

static auto GetLEB128Size(std::span<const std::uint8_t> data) -> std::size_t {
    std::size_t offset = 0;
    std::uint8_t byte;
    do {
        if (offset + sizeof(std::uint8_t) > data.size()) {
            Panic("ReadLEB128 ran out of input");
        }

        byte = data[offset++];
    } while ((byte & 0x80) != 0);

    return offset;
}

static auto GetSize(Encoding enc, std::span<const std::uint8_t> data) -> std::size_t {
    if (enc == DW_EH_PE_omit) {
        return 0;
    }

    switch (enc & SizeMask) {
        case 1:
            return GetLEB128Size(data);
        case 2:
            return 2;
        case 3:
            return 4;
        case 4:
            return 8;
        default:
            Panic("Invalid encoding");
    }
}

template <bool SIGNED>
static auto ReadLEB128(std::span<const std::uint8_t> data) -> decltype(auto) {
    using ResultT = std::conditional_t<SIGNED, std::int64_t, std::uint64_t>;
    
    ResultT result = 0;
    std::size_t shift = 0;

    std::size_t offset = 0;
    std::uint8_t byte;
    do {
        if (offset + sizeof(std::uint8_t) > data.size()) {
            Panic("ReadLEB128 ran out of input");
        }

        byte = data[offset++];
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while ((byte & 0x80) != 0);

    if constexpr (SIGNED) {
        // sign extend
        constexpr const auto nbits = sizeof(ResultT) * CHAR_BIT;
        if ((shift < nbits) && ((byte & 0x40) != 0)) {
            result = (result << (nbits - shift)) >> (nbits - shift);
        }
    }

    return result;
}

static auto ReadSigned(Encoding enc, std::span<const std::uint8_t> data) -> std::int64_t {
    switch (enc & TypeMask) {
        case DW_EH_PE_sleb128:
            return ReadLEB128<true>(data);
        case DW_EH_PE_sdata2:
            if (sizeof(std::int16_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return static_cast<std::int64_t>(*reinterpret_cast<const std::int16_t*>(data.data()));
        case DW_EH_PE_sdata4:
            if (sizeof(std::int32_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return static_cast<std::int64_t>(*reinterpret_cast<const std::int32_t*>(data.data()));
        case DW_EH_PE_sdata8:
            if (sizeof(std::int64_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return *reinterpret_cast<const std::int64_t*>(data.data());
        default:
            Panic("Invalid encoding type");
    }
}

static auto ReadUnsigned(Encoding enc, std::span<const std::uint8_t> data) -> std::uint64_t {
    switch (enc & TypeMask) {
        case DW_EH_PE_sleb128:
            return ReadLEB128<false>(data);
        case DW_EH_PE_sdata2:
            if (sizeof(std::uint16_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return static_cast<std::uint64_t>(*reinterpret_cast<const std::uint16_t*>(data.data()));
        case DW_EH_PE_sdata4:
            if (sizeof(std::uint32_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t*>(data.data()));
        case DW_EH_PE_sdata8:
            if (sizeof(std::uint64_t) > data.size()) {
                Panic("ReadSigned ran out of input");
            }
            return *reinterpret_cast<const std::uint64_t*>(data.data());
        default:
            Panic("Invalid encoding type");
    }
}

struct LibNXExtension {
    char signature[4];
    std::int32_t got_start;
    std::int32_t got_end;
};

static constexpr const char cLibNXMagic[] = { 'L', 'N', 'Y', '0' };

class ELFBuilder {
public:
    ELFBuilder() {
        std::memset(std::addressof(mHeader), 0, sizeof(mHeader));
        mHeader.e_ident[EI_MAG0] = ELFMAG0;
        mHeader.e_ident[EI_MAG1] = ELFMAG1;
        mHeader.e_ident[EI_MAG2] = ELFMAG2;
        mHeader.e_ident[EI_MAG3] = ELFMAG3;
        mHeader.e_ident[EI_CLASS] = ELFCLASS64;
        mHeader.e_ident[EI_DATA] = ELFDATA2LSB;
        mHeader.e_ident[EI_VERSION] = EV_CURRENT;
        mHeader.e_ident[EI_OSABI] = ELFOSABI_NONE;
        mHeader.e_ident[EI_ABIVERSION] = 0;
        mHeader.e_type = ET_DYN;
        mHeader.e_machine = EM_AARCH64;
        mHeader.e_version = EV_CURRENT;
        mHeader.e_entry = 0;
        mHeader.e_phoff = sizeof(mHeader);
        // e_shoff is written later
        mHeader.e_flags = 0;
        mHeader.e_ehsize = sizeof(mHeader);
        mHeader.e_phentsize = sizeof(Elf64_Phdr);
        mHeader.e_phnum = cPhdrCount;
        mHeader.e_shentsize = sizeof(Elf64_Shdr);
        // e_shnum is written later
        // e_shstrndx is written later

        mPhdrs.resize(cPhdrCount);
        mShdrs.reserve(SectionType_Count);
        addNullSection();
    }

    auto build(const NSOFile& nso) -> void;
    auto write(std::string_view path) const -> void;

private:
    static constexpr const auto cPhdrCount = Segment_Count + 1; // 3 segments + dynamic
    static constexpr const auto cDynamicIndex = cPhdrCount - 1;
    static constexpr const std::size_t cProgramAlign = 0x10000;
    static constexpr const std::size_t cDynamicAlign = 8;

    struct ProgBits {
        std::span<const std::uint8_t> data;
        std::size_t align;
    };

    // assumptions based on the layout of official NSOs
    // the issue is with unofficial NSOs where people don't follow the same section ordering as Nintendo
    enum SectionType {
        // .text
        SectionType_EX            = 0x00, // non-plt portion of .text
        SectionType_PLT                 , // match plt pattern
        // .rodata
        SectionType_ROCRT_INITRO        , // only exists in newer versions
        SectionType_NX_DEBUGLINK        , // parsed from module header in newer versions, start of .rodata in older versions
        SectionType_ROCRT_INFO          , // only separate this in newer versions, we'll keep it as part of .text in older versions
        SectionType_REL_DYN             , // parsed from .dynamic
        SectionType_RELA_DYN            , // parsed from .dynamic
        SectionType_REL_PLT             , // parsed from .dynamic
        SectionType_RELA_PLT            , // parsed from .dynamic
        SectionType_RELR_DYN            , // parsed from .dynamic
        SectionType_HASH                , // parsed from .dynamic
        SectionType_GNU_HASH            , // parsed from .dynamic
        SectionType_DYN_SYM             , // parsed from .dynamic
        SectionType_DYN_STR             , // parsed from .dynamic
        SectionType_RO                  , // between .dynstr and .gcc_except_table/.eh_frame_hdr
        SectionType_GCC_EXCEPT_TABLE    , // parse from .eh_frame
        SectionType_EH_FRAME_HDR        , // parsed from module header
        SectionType_EH_FRAME            , // parsed from .eh_frame_hdr
        SectionType_API_INFO            , // region between .eh_frame and .note.gnu.build-id
        SectionType_GNU_BUILDID         , // parsed from module header in newer versions, searched for in older versions (nnSdk searches the last 0x2000 bytes of .rodata)
        // .data
        SectionType_INIT_ARRAY          , // parsed from .dynamic
        SectionType_FINI_ARRAY          , // parsed from .dynamic
        SectionType_TDATA               , // TODO: start/end can be found in the arguments for __nnmusl_init_dso, but that would be more involved to parse out
        SectionType_TBSS                , // TODO: start/end can be found in the arguments for __nnmusl_init_dso, but that would be more involved to parse out
        SectionType_DATA_REL_RO         , // relocations not in .init_array/.fini_array/.got/.got.plt/.atexit
        SectionType_DYNAMIC             , // parsed from module header
        SectionType_GOT                 , // between .dynamic and .got.plt on newer versions, between .got.plt and .init_array on older versions (verify against relocations)
        SectionType_GOT_PLT             , // parsed from .dynamic
        SectionType_ROCRT_ALIGN_RELROEND, // between relro region and RW
        SectionType_RW                  , // remaining range
        SectionType_ATEXIT              , // .rel.dyn or .rela.dyn relocations after .got/.got.plt/.init_array/.fini_array (whichever comes last)
        SectionType_ROCRT_ALIGN_BSSEND  , // TODO: padding after .bss - no good way of telling what's padding and what's not
        // .bss
        SectionType_ZI                  , // .bss

        SectionType_Count,
    };

    // Nintendo uses EX, RO, RW, and ZI for .text, .rodata, .data, and .bss, respectively
    static constexpr const std::array<std::string_view, SectionType_Count> cSectionNames = {
        "EX",
        ".plt",
        ".rocrt.initro",
        ".nx_debuglink",
        ".rocrt.info",
        ".rel.dyn",
        ".rela.dyn",
        ".rel.plt",
        ".rela.plt",
        ".relr.dyn",
        ".hash",
        ".gnu.hash",
        ".dynsym",
        ".dynstr",
        "RO",
        ".gcc_except_table",
        ".eh_frame_hdr",
        ".eh_frame",
        ".api_info",
        ".note.gnu.build-id",
        ".init_array",
        ".fini_array",
        ".tdata",
        ".tbss",
        ".data.rel.ro",
        ".dynamic",
        ".got",
        ".got.plt",
        ".rocrt.align.relroend",
        "RW",
        ".atexit",
        ".rocrt.align.bssend",
        "ZI",
    };

    struct Context {
        const NSOFile& nso;
        std::size_t header_offset;
        const ModuleHeader* header;
        std::uint32_t rocrt_version;
        const LibNXExtension* libnx_extension;
        const Elf64_Dyn* rel;
        const Elf64_Dyn* rel_size;
        const Elf64_Dyn* rela;
        const Elf64_Dyn* rela_size;
        const Elf64_Dyn* plt_rel;
        const Elf64_Dyn* plt_rel_size;
        const Elf64_Dyn* plt_rel_type;
        const Elf64_Dyn* relr;
        const Elf64_Dyn* relr_size;
        const Elf64_Dyn* hash;
        const Elf64_Dyn* gnu_hash;
        const Elf64_Dyn* dyn_sym;
        const Elf64_Dyn* dyn_str;
        const Elf64_Dyn* dyn_str_size;
        const Elf64_Dyn* init_array;
        const Elf64_Dyn* init_array_size;
        const Elf64_Dyn* fini_array;
        const Elf64_Dyn* fini_array_size;
        const Elf64_Dyn* got_plt;
        std::unordered_set<std::uint64_t> relocations{};
        std::size_t plt_rel_index = SHN_UNDEF;
        std::size_t dyn_str_index = SHN_UNDEF;
        std::size_t max_plt_reloc = std::numeric_limits<std::size_t>::min();
    };

    auto addSection(Elf64_Word type, std::string_view name) -> Elf64_Shdr& {
        auto& shdr = mShdrs.emplace_back();
        shdr.sh_name = mSectionNames.size();
        mSectionNames.insert(mSectionNames.end(), name.begin(), name.end());
        mSectionNames.push_back('\0');
        shdr.sh_type = type;
        return shdr;
    }

    auto addNullSection() -> void {
        auto& null_shdr = addSection(SHT_NULL, "");
        null_shdr.sh_flags = 0;
        null_shdr.sh_addr = 0;
        null_shdr.sh_offset = 0;
        null_shdr.sh_size = 0;
        null_shdr.sh_link = 0;
        null_shdr.sh_info = 0;
        null_shdr.sh_addralign = 0;
        null_shdr.sh_entsize = 0;
    }

    auto addProgBits(std::span<const std::uint8_t> data, std::size_t align) -> void {
        mProgBits.emplace_back(data, align);
    }

    auto splitSections(const NSOFile& nso) -> void;
    auto splitText(Context& ctx) -> void;
    auto splitRodata(Context& ctx) -> void;
    auto splitData(Context& ctx) -> void;
    auto splitBss(Context& ctx) -> void;

    Elf64_Ehdr mHeader;
    std::vector<ProgBits> mProgBits;
    std::vector<Elf64_Phdr> mPhdrs;
    std::vector<Elf64_Shdr> mShdrs;
    std::vector<char> mSectionNames;
};

static auto Imm12(std::uint32_t value) -> std::uint32_t {
    return value >> 10 & 0xfff;
}

constexpr const auto cPltResolverInstructionCount = 8;
constexpr const auto cPltResolverSize = cPltResolverInstructionCount * sizeof(std::uint32_t);
constexpr const std::uint32_t cPltResolverValues[cPltResolverInstructionCount] = {
    0xa9bf7bf0u, 0x90000010u, 0xf9400211u, 0x91000210u, 0xd61f0220u, 0xd503201fu, 0xd503201fu, 0xd503201fu,
};
constexpr const std::uint32_t cPltResolverMasks[cPltResolverInstructionCount] = {
    0xffffffffu, 0x9f00001fu, 0xffC003ffu, 0xffc003ffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
};
static_assert(sizeof(cPltResolverValues) == cPltResolverSize && sizeof(cPltResolverMasks) == cPltResolverSize);

constexpr const auto cPltEntryInstructionCount = 4;
constexpr const auto cPltEntrySize = cPltEntryInstructionCount * sizeof(std::uint32_t);
constexpr const std::uint32_t cPltEntryValues[cPltEntryInstructionCount] = {
    0x90000010u, 0xf9400211u, 0x91000210u, 0xd61f0220u,
};
constexpr const std::uint32_t cPltEntryMasks[cPltEntryInstructionCount] = {
    0x9f00001fu, 0xffC003ffu, 0xffc003ffu, 0xffffffffu,
};
static_assert(sizeof(cPltEntryValues) == cPltEntrySize && sizeof(cPltEntryMasks) == cPltEntrySize);

static auto MatchPltResolver(std::span<const std::uint8_t> data) -> std::size_t {
    /*
        .plt begins with the runtime resolver thunk which has the following form (.got.plt[2] contains the resolver function pointer)
            stp x16, x30, [sp, -#0x10]!
            adrp x16, &(.got.plt[2])
            ldr x17, [x16, :lo12:&(.got.plt[2])]
            add x16, x16, :lo12:&(.got.plt[2])
            br x17
            nop
            nop
            nop
        we need to match this function to find the beginning of the .plt
    */
    
    std::size_t offset = 0;
    while (offset + cPltResolverSize <= data.size()) {
        const auto instructions = reinterpret_cast<const std::uint32_t*>(data.data() + offset);
        bool matched = true;
        for (std::size_t i = 0; i < cPltResolverInstructionCount; ++i) {
            if ((instructions[i] & cPltResolverMasks[i]) != cPltResolverValues[i]) {
                matched = false;
                break;
            }
        }

        if (matched) {
            // verify ldr and add are using the same offset
            const auto ldr_offset = Imm12(instructions[2]) * 8;
            const auto add_offset = Imm12(instructions[3]);

            if (ldr_offset == add_offset) {
                return offset;
            }
        }

        offset += sizeof(std::uint32_t);
    }

    return std::numeric_limits<std::size_t>::max();
}

static auto MatchAllPltEntries(std::span<const std::uint8_t> data) -> std::size_t {
    /*
        once we have the start of the .plt, then we need to match .plt entries of the following form
            adrp x16, &(.got.plt[index])
            ldr x17, [x16, :lo12:&(.got.plt[index])]
            add x16, x16, :lo12:&(.got.plt[index])
            br x17
        this should extend until the end of the executable region (unless someone decided to do something funky with their linker script)
            TODO: turns out some games do have code after .plt - is this another section or just weird ordering?
    */

    std::size_t offset = 0;
    while (offset + cPltEntrySize <= data.size()) {
        const auto instructions = reinterpret_cast<const std::uint32_t*>(data.data() + offset);
        bool matched = true;
        for (std::size_t i = 0; i < cPltEntryInstructionCount; ++i) {
            if ((instructions[i] & cPltEntryMasks[i]) != cPltEntryValues[i]) {
                matched = false;
                break;
            }
        }

        if (!matched) {
            break;
        }

        // verify ldr and add are using the same offset
        const auto ldr_offset = Imm12(instructions[1]) * 8;
        const auto add_offset = Imm12(instructions[2]);

        if (ldr_offset != add_offset) {
            break;
        }

        offset += cPltEntrySize;
    }

    return offset;
}

static auto ReadEhFrame(
    const NSOFile& nso,
    std::span<const std::uint8_t> data,
    std::size_t eh_frame_hdr_start,
    std::size_t eh_frame_start,
    std::optional<Range>& lsda_range
) -> std::size_t {
    auto current_eh_frame_offset = eh_frame_start;
    auto min_lsda = std::numeric_limits<std::size_t>::max();
    auto max_lsda = std::numeric_limits<std::size_t>::min();
    bool has_lsda = false;
    Encoding lsda_encoding = DW_EH_PE_omit;
    Encoding ptr_encoding = DW_EH_PE_omit;
    while (true) {
        if (!nso.isInRodata(current_eh_frame_offset, sizeof(std::uint32_t))) {
            Panic("End of .rodata reached before a terminator was found");
        }

        std::uint64_t length = *reinterpret_cast<const std::uint32_t*>(data.data() + current_eh_frame_offset - nso.getRodataOffset());
        current_eh_frame_offset += sizeof(std::uint32_t);
        if (length == 0) {
            break;
        } else if (length == 0xffff'ffff) {
            if (!nso.isInRodata(current_eh_frame_offset, sizeof(std::uint64_t))) {
                Panic("End of .rodata reached before a terminator was found ", std::hex, current_eh_frame_offset);
            }

            length = *reinterpret_cast<const std::uint64_t*>(data.data() + current_eh_frame_offset - nso.getRodataOffset());
            current_eh_frame_offset += sizeof(std::uint64_t);
        }

        if (!nso.isInRodata(current_eh_frame_offset, length)) {
            Panic(".eh_frame entry extends past end of .rodata");
        }

        if (length < sizeof(std::uint32_t)) {
            Panic(".eh_frame entry is too small to be valid");
        }

        const auto id = *reinterpret_cast<const std::uint32_t*>(data.data() + current_eh_frame_offset - nso.getRodataOffset());
        if (id == 0) {
            // CIE
            if (length < sizeof(std::uint32_t) + sizeof(std::uint8_t)) {
                Panic(".eh_frame CIE is too small to be valid");
            }

            const auto version_offset = current_eh_frame_offset + sizeof(std::uint32_t);
            if (*reinterpret_cast<const std::uint8_t*>(data.data() + version_offset - nso.getRodataOffset()) != 1) {
                Panic("Invalid CIE version");
            }

            auto aug_str_offset = version_offset + sizeof(std::uint8_t);
            std::size_t aug_str_length = 0;
            std::string aug_str = "";
            while (true) {
                if (!nso.isInRodata(aug_str_offset, sizeof(char))) {
                    Panic(".eh_frame CIE augmentation string was not null-terminated before the end of .rodata");
                }

                const auto c = *reinterpret_cast<const std::uint8_t*>(data.data() + aug_str_offset++ - nso.getRodataOffset());
                if (c == '\0') {
                    break;
                }

                aug_str += c;
            }
            
            has_lsda = false; lsda_encoding = DW_EH_PE_omit; ptr_encoding = DW_EH_PE_omit;
            if (aug_str.starts_with('z')) {
                auto current_offset = aug_str_offset;
                if (aug_str.find("eh") != std::string::npos) { // skip EH data
                    current_offset += 8;
                }
                current_offset += GetLEB128Size(std::span(data).subspan(current_offset - nso.getRodataOffset())); // code alignment factor
                current_offset += GetLEB128Size(std::span(data).subspan(current_offset - nso.getRodataOffset())); // data alignment factor
                current_offset += sizeof(std::uint8_t); // return address register

                const auto aug_size = ReadLEB128<false>(std::span(data).subspan(current_offset - nso.getRodataOffset()));
                current_offset += GetLEB128Size(std::span(data).subspan(current_offset - nso.getRodataOffset()));

                if (!nso.isInRodata(current_offset, aug_size)) {
                    Panic(".eh_frame CIE augmentation data does not fit in .rodata ", std::hex, current_offset, " ", aug_size, " ", aug_str);
                }

                std::size_t aug_data_offset = 0;
                for (const auto c : aug_str.substr(1)) {
                    switch (c) {
                        case 'P': {
                            if (aug_data_offset + sizeof(Encoding) > aug_size) {
                                Panic(".eh_frame CIE augmentation data is too small");
                            }

                            const auto offset = current_offset + aug_data_offset;
                            const auto personality_encoding = *reinterpret_cast<const Encoding*>(data.data() + offset - nso.getRodataOffset());
                            aug_data_offset += sizeof(Encoding);
                            aug_data_offset += GetSize(personality_encoding, std::span(data).subspan(offset + sizeof(Encoding) - nso.getRodataOffset()));
                            break;
                        }
                        case 'L': {
                            if (aug_data_offset + sizeof(Encoding) > aug_size) {
                                Panic(".eh_frame CIE augmentation data is too small");
                            }

                            has_lsda = true;
                            lsda_encoding = *reinterpret_cast<const Encoding*>(data.data() + current_offset + aug_data_offset - nso.getRodataOffset());
                            aug_data_offset += sizeof(Encoding);
                            break;
                        }
                        case 'R': {
                            if (aug_data_offset + sizeof(Encoding) > aug_size) {
                                Panic(".eh_frame CIE augmentation data is too small");
                            }

                            ptr_encoding = *reinterpret_cast<const Encoding*>(data.data() + current_offset + aug_data_offset - nso.getRodataOffset());
                            aug_data_offset += sizeof(Encoding);
                            break;
                        }
                        default:
                            Panic("Invalid CIE augmentation string ", aug_str);
                    }
                }
            }
        } else {
            // FDE
            if (has_lsda) {
                auto fde_offset = current_eh_frame_offset + sizeof(std::uint32_t);
                fde_offset += GetSize(ptr_encoding, std::span(data).subspan(fde_offset - nso.getRodataOffset())); // PC begin
                fde_offset += GetSize(ptr_encoding, std::span(data).subspan(fde_offset - nso.getRodataOffset())); // PC range

                const auto aug_size = ReadLEB128<false>(std::span(data).subspan(fde_offset - nso.getRodataOffset()));
                fde_offset += GetLEB128Size(std::span(data).subspan(fde_offset - nso.getRodataOffset()));

                if (!nso.isInRodata(fde_offset, aug_size)) {
                    Panic(".eh_frame FDE augmentation data does not fit in .rodata");
                }

                std::size_t lsda_offset;
                switch (lsda_encoding & ApplyTypeMask) {
                    case DW_EH_PE_absptr: lsda_offset = 0; break;
                    case DW_EH_PE_pcrel: lsda_offset = fde_offset; break;
                    case DW_EH_PE_datarel: lsda_offset = eh_frame_hdr_start; break;
                    default: Panic("Invalid pointer apply type");
                }

                const auto lsda_ptr_data = std::span(data).subspan(fde_offset - nso.getRodataOffset());
                if (lsda_encoding & IsSignedMask) {
                    lsda_offset = static_cast<std::size_t>(static_cast<std::int64_t>(lsda_offset) + ReadSigned(lsda_encoding, lsda_ptr_data));
                } else {
                    lsda_offset += ReadUnsigned(lsda_encoding, lsda_ptr_data);
                }

                min_lsda = std::min(lsda_offset, min_lsda);
                max_lsda = std::max(lsda_offset, max_lsda);
            }
        }

        current_eh_frame_offset += length;
    }

    if (min_lsda != std::numeric_limits<std::size_t>::max() && max_lsda != std::numeric_limits<std::size_t>::min()) {
        if (!nso.isInRodata(min_lsda) || !nso.isInRodata(max_lsda)) {
            Panic("Language-specific data area must be in .rodata");
        }

        auto offset = max_lsda;
        if (!nso.isInRodata(offset, sizeof(Encoding))) {
            Panic("Language-specific data area does not fit in .rodata");
        }

        const auto region_begin_encoding = *reinterpret_cast<const Encoding*>(data.data() + offset - nso.getRodataOffset());
        offset += sizeof(Encoding);
        if (region_begin_encoding != DW_EH_PE_omit) {
            offset += GetSize(region_begin_encoding, std::span(data).subspan(offset - nso.getRodataOffset()));
        }

        if (!nso.isInRodata(offset, sizeof(Encoding))) {
            Panic("Language-specific data area does not fit in .rodata");
        }

        const auto type_table_encoding = *reinterpret_cast<const Encoding*>(data.data() + offset - nso.getRodataOffset());
        offset += sizeof(Encoding);
        std::size_t type_table_offset = 0;
        if (type_table_encoding != DW_EH_PE_omit) {
            // if we have a type table, then it must come last (the type table offset is to the end of the type table)
            offset += ReadLEB128<false>(std::span(data).subspan(offset - nso.getRodataOffset()));
            offset += GetLEB128Size(std::span(data).subspan(offset - nso.getRodataOffset())); // this offset is relative to the end of this offset
        } else {
            if (!nso.isInRodata(offset, sizeof(Encoding))) {
                Panic("Language-specific data are does not fit in .rodata");
            }
            const auto call_site_encoding = *reinterpret_cast<const Encoding*>(data.data() + offset - nso.getRodataOffset());
            offset += sizeof(Encoding);

            const auto call_site_table_size = ReadLEB128<false>(std::span(data).subspan(offset - nso.getRodataOffset()));
            offset += GetLEB128Size(std::span(data).subspan(offset - nso.getRodataOffset()));
    
            // see if we have any actions to handle
            std::size_t max_action = 0;
            for (auto table_offset = offset; table_offset < offset + call_site_table_size; /* ... */) {
                table_offset += GetSize(call_site_encoding, std::span(data).subspan(table_offset - nso.getRodataOffset())); // pos
                table_offset += GetSize(call_site_encoding, std::span(data).subspan(table_offset - nso.getRodataOffset())); // range
                table_offset += GetSize(call_site_encoding, std::span(data).subspan(table_offset - nso.getRodataOffset())); // landing pad
                const auto action = ReadLEB128<false>(std::span(data).subspan(table_offset - nso.getRodataOffset()));
                table_offset += GetLEB128Size(std::span(data).subspan(table_offset - nso.getRodataOffset()));
                if (action != 0) { // not cleanup
                    max_action = std::max(action - 1, max_action);
                }
            }

            offset += call_site_table_size;

            if (max_action != 0) {
                offset += max_action;
                offset += GetLEB128Size(std::span(data).subspan(offset - nso.getRodataOffset())); // filter
                const auto next_offset = ReadLEB128<false>(std::span(data).subspan(offset - nso.getRodataOffset()));
                offset += GetLEB128Size(std::span(data).subspan(offset - nso.getRodataOffset()));
                offset += next_offset;
            }
        }

        lsda_range.emplace();
        lsda_range->start = static_cast<std::uint32_t>(min_lsda);
        lsda_range->size = static_cast<std::uint32_t>(offset - min_lsda);
    }

    return current_eh_frame_offset - eh_frame_start;;
}

auto ELFBuilder::splitText(Context& ctx) -> void {
    const auto& segment_data = ctx.nso.getText();

    if (segment_data.size() < cMinimumRocrtInitSize) {
        Panic("Invalid .text segment");
    }

    const auto rocrt_init = reinterpret_cast<const RocrtInit*>(segment_data.data());
    ctx.rocrt_version = GetRocrtVersion(rocrt_init);
    // catch libnx being goofy
    if (ctx.rocrt_version == 1 && std::memcmp(std::addressof(ctx.header->relro_start), cLibNXMagic, sizeof(cLibNXMagic)) == 0) {
        ctx.rocrt_version = 0;
        ctx.libnx_extension = reinterpret_cast<const LibNXExtension*>(std::addressof(ctx.header->relro_start));
    }
    
    // EX
    const auto plt_begin = MatchPltResolver(segment_data);
    if (plt_begin == std::numeric_limits<std::size_t>::max()) {
        // if no .plt found, then assign the entire executable region to .text
        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_EX]);
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = ctx.nso.getTextOffset();
        shdr.sh_offset = mPhdrs[Segment_Text].p_offset;
        shdr.sh_size = segment_data.size();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 6;
        shdr.sh_entsize = 0;
        return;
    } else {
        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_EX]);
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = ctx.nso.getTextOffset();
        shdr.sh_offset = mPhdrs[Segment_Text].p_offset;
        shdr.sh_size = plt_begin;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 6;
        shdr.sh_entsize = 0;
    }

    // .plt
    const auto total_entry_size = MatchAllPltEntries(std::span(segment_data).subspan(plt_begin + cPltResolverSize));
    auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_PLT]);
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR | 2 << 0x1c; // not sure what the SHF_MASKPROC flags are here
    shdr.sh_addr = ctx.nso.getTextOffset() + plt_begin;
    shdr.sh_offset = mPhdrs[Segment_Text].p_offset + plt_begin;
    shdr.sh_size = cPltResolverSize + total_entry_size;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1 << 4;
    shdr.sh_entsize = 0;

    const auto total_size = plt_begin + cPltResolverSize + total_entry_size;
    if (segment_data.size() > total_size) {
        auto& shdr = addSection(SHT_PROGBITS, ".text.1");
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = ctx.nso.getTextOffset() + total_size;
        shdr.sh_offset = mPhdrs[Segment_Text].p_offset + total_size;
        shdr.sh_size = segment_data.size() - total_size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 2;
        shdr.sh_entsize = 0;
    }
}

auto ELFBuilder::splitRodata(Context& ctx) -> void {
    const auto& segment_data = ctx.nso.getRodata();
    const auto start_offset = mPhdrs[Segment_Ro].p_offset;

    // .rocrt.initro
    if (ctx.rocrt_version == 1) {
        if (segment_data.size() < sizeof(RocrtInit)) {
            Panic("Invalid .rodata segment");
        }

        const auto rocrt_init = reinterpret_cast<const RocrtInit*>(segment_data.data());
        if (rocrt_init->entry == 1) { // failsafe for unofficial NSOs that pass the rocrt version check but don't actually have this section
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_ROCRT_INITRO]);
            shdr.sh_flags = SHF_ALLOC;
            shdr.sh_addr = ctx.nso.getRodataOffset();
            shdr.sh_offset = start_offset;
            shdr.sh_size = sizeof(RocrtInit);
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = alignof(RocrtInit);
            shdr.sh_entsize = 0;
        } else {
            if (!ctx.nso.isInText(rocrt_init->rocrt_info_offset, cMinimumRocrtInitSize)) {
                Panic(".rocrt.init must be in .text");
            }

            ctx.rocrt_version = 0;
            if (ctx.nso.isInText(rocrt_init->rocrt_info_offset, cMinimumRocrtInitSize + sizeof(LibNXExtension))) {
                const auto ext = reinterpret_cast<const LibNXExtension*>(segment_data.data() + rocrt_init->rocrt_info_offset + cMinimumRocrtInitSize);
                if (std::memcmp(ext->signature, cLibNXMagic, sizeof(cLibNXMagic)) == 0) {
                    ctx.libnx_extension = ext;
                    std::cout << "[INFO] Detected LibNX extension\n";
                }
            }
        }
    }

    // .nx_debuglink
    if (const auto range = ctx.nso.findModuleNameRange()) {
        if (!ctx.nso.isInRodata(range->start, range->size)) {
            Panic(".nx_debuglink must be in .rodata");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_NX_DEBUGLINK]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = range->start;
        shdr.sh_offset = start_offset + range->start - ctx.nso.getRodataOffset();
        shdr.sh_size = range->size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(NxDebuglink);
        shdr.sh_entsize = 0;
    } else {
        Panic("No .nx_debuglink");
    }

    // .rocrt.info
    if (ctx.rocrt_version == 1) {
        if (!ctx.nso.isInRodata(ctx.header_offset, sizeof(ModuleHeader))) {
            Panic(".rocrt.info must be in .rodata");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_ROCRT_INFO]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.header_offset;
        shdr.sh_offset = start_offset + ctx.header_offset - ctx.nso.getRodataOffset();
        shdr.sh_size = sizeof(ModuleHeader);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(ModuleHeader);
        shdr.sh_entsize = 0;

        // we know that this is in-bounds because we would have panicked above if it wasn't
        const auto initro = reinterpret_cast<const RocrtInit*>(segment_data.data());
        // these two structures *should* be adjacent to each other, but to avoid creating an invalid section,
        // make sure that the version starts where the header ends
        if (initro->rocrt_version_offset == ctx.header_offset - ctx.nso.getRodataOffset() + sizeof(ModuleHeader)) {
            shdr.sh_size += sizeof(RocrtVersion);
        }
    } else {
        // .rocrt.info is in .text on older versions so we'll just ignore it
    }

    std::size_t rel_index = SHN_UNDEF;
    std::size_t rela_index = SHN_UNDEF;

    // .rel.dyn
    if (ctx.rel && ctx.rel_size) {
        if (!ctx.nso.isInRodata(ctx.rel->d_un.d_ptr, ctx.rel_size->d_un.d_val)) {
            Panic(".rel.dyn must be in .rodata");
        }

        const auto rodata_offset = ctx.rel->d_un.d_ptr - ctx.nso.getRodataOffset();

        rel_index = mShdrs.size();
        auto& shdr = addSection(SHT_REL, cSectionNames[SectionType_REL_DYN]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.rel->d_un.d_ptr;
        shdr.sh_offset = start_offset + rodata_offset;
        shdr.sh_size = ctx.rel_size->d_un.d_val;
        shdr.sh_link = 0; // linked to .dynsym
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Rel);
        shdr.sh_entsize = sizeof(Elf64_Rel);

        const auto count = ctx.rel_size->d_un.d_val / sizeof(Elf64_Rel);
        for (const auto& rel : std::span(reinterpret_cast<const Elf64_Rel*>(segment_data.data() + rodata_offset), count)) {
            ctx.relocations.insert(rel.r_offset);
        }
    }

    // .rela.dyn
    if (ctx.rela && ctx.rela_size) {
        if (!ctx.nso.isInRodata(ctx.rela->d_un.d_ptr, ctx.rela_size->d_un.d_val)) {
            Panic(".rela.dyn must be in .rodata");
        }

        const auto rodata_offset = ctx.rela->d_un.d_ptr - ctx.nso.getRodataOffset();

        rela_index = mShdrs.size();
        auto& shdr = addSection(SHT_RELA, cSectionNames[SectionType_RELA_DYN]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.rela->d_un.d_ptr;
        shdr.sh_offset = start_offset + rodata_offset;
        shdr.sh_size = ctx.rela_size->d_un.d_val;
        shdr.sh_link = 0; // linked to .dynsym
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Rela);
        shdr.sh_entsize = sizeof(Elf64_Rela);

        const auto count = ctx.rela_size->d_un.d_val / sizeof(Elf64_Rela);
        for (const auto& rel : std::span(reinterpret_cast<const Elf64_Rela*>(segment_data.data() + rodata_offset), count)) {
            ctx.relocations.insert(rel.r_offset);
        }
    }

    if (ctx.plt_rel && ctx.plt_rel_size && ctx.plt_rel_type) {
        const auto rodata_offset = ctx.plt_rel->d_un.d_ptr - ctx.nso.getRodataOffset();
        switch (ctx.plt_rel_type->d_un.d_val) {
            // .rel.plt
            case DT_REL: {
                if (!ctx.nso.isInRodata(ctx.plt_rel->d_un.d_ptr, ctx.plt_rel_size->d_un.d_val)) {
                    Panic(".rel.plt must be in .rodata");
                }

                ctx.plt_rel_index = mShdrs.size();
                auto& shdr = addSection(SHT_REL, cSectionNames[SectionType_REL_PLT]);
                shdr.sh_flags = SHF_ALLOC; // add SHF_INFO_LINK later if .got.plt exists
                shdr.sh_addr = ctx.plt_rel->d_un.d_ptr;
                shdr.sh_offset = start_offset + rodata_offset;
                shdr.sh_size = ctx.plt_rel_size->d_un.d_val;
                shdr.sh_link = 0; // linked to .dynsym
                shdr.sh_info = 0; // linked to .got.plt
                shdr.sh_addralign = alignof(Elf64_Rel);
                shdr.sh_entsize = sizeof(Elf64_Rel);

                const auto count = ctx.plt_rel_size->d_un.d_val / sizeof(Elf64_Rel);
                for (const auto& rel : std::span(reinterpret_cast<const Elf64_Rel*>(segment_data.data() + rodata_offset), count)) {
                    ctx.max_plt_reloc = std::max(ctx.max_plt_reloc, rel.r_offset + sizeof(void*));
                }
                break;
            }
            // .rela.plt
            case DT_RELA: {
                if (!ctx.nso.isInRodata(ctx.plt_rel->d_un.d_ptr, ctx.plt_rel_size->d_un.d_val)) {
                    Panic(".rela.plt must be in .rodata");
                }

                ctx.plt_rel_index = mShdrs.size();
                auto& shdr = addSection(SHT_RELA, cSectionNames[SectionType_RELA_PLT]);
                shdr.sh_flags = SHF_ALLOC; // add SHF_INFO_LINK later if .got.plt exists
                shdr.sh_addr = ctx.plt_rel->d_un.d_ptr;
                shdr.sh_offset = start_offset + rodata_offset;
                shdr.sh_size = ctx.plt_rel_size->d_un.d_val;
                shdr.sh_link = 0; // linked to .dynsym
                shdr.sh_info = 0; // linked to .got.plt
                shdr.sh_addralign = alignof(Elf64_Rela);
                shdr.sh_entsize = sizeof(Elf64_Rela);

                const auto count = ctx.plt_rel_size->d_un.d_val / sizeof(Elf64_Rela);
                for (const auto& rel : std::span(reinterpret_cast<const Elf64_Rela*>(segment_data.data() + rodata_offset), count)) {
                    ctx.max_plt_reloc = std::max(ctx.max_plt_reloc, rel.r_offset + sizeof(void*));
                }
                break;
            }
            default:
                Panic("Invalid .plt relocation type");
        }
    }

    // .relr.dyn
    if (ctx.relr && ctx.relr_size) {
        if (!ctx.nso.isInRodata(ctx.relr->d_un.d_ptr, ctx.relr_size->d_un.d_val)) {
            Panic(".relr.dyn must be in .rodata");
        }

        const auto rodata_offset = ctx.relr->d_un.d_ptr - ctx.nso.getRodataOffset();

        auto& shdr = addSection(SHT_RELR, cSectionNames[SectionType_RELR_DYN]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.relr->d_un.d_ptr;
        shdr.sh_offset = start_offset + rodata_offset;
        shdr.sh_size = ctx.relr_size->d_un.d_val;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Relr);
        shdr.sh_entsize = sizeof(Elf64_Relr);

        std::size_t target = 0;
        const auto count = ctx.relr_size->d_un.d_val / sizeof(Elf64_Relr);
        for (auto rel : std::span(reinterpret_cast<const Elf64_Relr*>(segment_data.data() + rodata_offset), count)) {
            if ((rel & 1) == 0) {
                ctx.relocations.insert(rel);
                target = rel + sizeof(void*);
            } else {
                for (std::size_t i = 0; (rel >>= 1) != 0; ++i) {
                    if (rel & 1) {
                        ctx.relocations.insert(target + i * sizeof(void*));
                    }
                }
                target += (sizeof(Elf64_Relr) * CHAR_BIT - 1) * sizeof(void*);
            }
        }
    }

    std::uint32_t sym_count = 0;
    std::size_t hash_index = SHN_UNDEF;
    std::size_t gnu_hash_index = SHN_UNDEF;

    // .hash
    if (ctx.hash) {
        if (!ctx.nso.isInRodata(ctx.hash->d_un.d_ptr, sizeof(ElfHashTable))) {
            Panic(".hash must be in .rodata");
        }

        const auto hash_table = reinterpret_cast<const ElfHashTable*>(segment_data.data() + ctx.hash->d_un.d_ptr - ctx.nso.getRodataOffset());
        const auto total_size = sizeof(ElfHashTable) + hash_table->nbucket * sizeof(std::uint32_t) + hash_table->nchain * sizeof(std::uint32_t);

        sym_count = hash_table->nchain;

        if (!ctx.nso.isInRodata(ctx.hash->d_un.d_ptr, total_size)) {
            Panic(".hash must be in .rodata");
        }

        hash_index = mShdrs.size();
        auto& shdr = addSection(SHT_HASH, cSectionNames[SectionType_HASH]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.hash->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.hash->d_un.d_ptr - ctx.nso.getRodataOffset();
        shdr.sh_size = total_size;
        shdr.sh_link = 0; // linked to .dynsym
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(ElfHashTable);
        shdr.sh_entsize = 0;
    }

    // .gnu.hash
    if (ctx.gnu_hash) {
        if (!ctx.nso.isInRodata(ctx.gnu_hash->d_un.d_ptr, sizeof(GnuHashTable))) {
            Panic(".gnu.hash must be in .rodata");
        }

        const auto base_offset = ctx.gnu_hash->d_un.d_ptr - ctx.nso.getRodataOffset();
        const auto hash_table = reinterpret_cast<const GnuHashTable*>(segment_data.data() + base_offset);
        const auto bucket_offset = sizeof(GnuHashTable) + hash_table->bloom_size * sizeof(std::uint64_t);
        auto total_size = bucket_offset + hash_table->nbucket * sizeof(std::uint32_t);

        if (!ctx.nso.isInRodata(ctx.gnu_hash->d_un.d_ptr, total_size)) {
            Panic(".gnu.hash must be in .rodata");
        }

        std::uint32_t max_bucket = 0;
        const auto buckets = reinterpret_cast<const std::uint32_t*>(segment_data.data() + base_offset + bucket_offset);
        for (const auto bucket : std::span(buckets, hash_table->nbucket)) {
            max_bucket = std::max(bucket, max_bucket);
        }

        if (max_bucket >= hash_table->sym_offset) {
            total_size += (max_bucket - hash_table->sym_offset) * sizeof(std::uint32_t);

            if (!ctx.nso.isInRodata(ctx.gnu_hash->d_un.d_ptr, total_size + sizeof(std::uint32_t))) {
                Panic(".gnu.hash must be in .rodata");
            }

            sym_count = max_bucket;
            auto current_pos = reinterpret_cast<const std::uint32_t*>(segment_data.data() + base_offset + total_size);
            while ((*current_pos++ & 1) == 0) {
                total_size += sizeof(std::uint32_t);
                ++sym_count;
                if (!ctx.nso.isInRodata(ctx.gnu_hash->d_un.d_ptr, total_size + sizeof(std::uint32_t))) {
                    Panic(".rodata ends before the end of .gnu.hash was found");
                }
            }

            total_size += sizeof(std::uint32_t);
            ++sym_count;
        } else {
            sym_count = hash_table->sym_offset;
            total_size += sizeof(std::uint32_t);
        }

        gnu_hash_index = mShdrs.size();
        auto& shdr = addSection(SHT_GNU_HASH, cSectionNames[SectionType_GNU_HASH]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.gnu_hash->d_un.d_ptr;
        shdr.sh_offset = start_offset + base_offset;
        shdr.sh_size = total_size;
        shdr.sh_link = 0; // linked to .dynsym
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(std::uint64_t);
        shdr.sh_entsize = 0;
    }

    std::size_t dyn_sym_index = SHN_UNDEF;

    // .dynsym
    if (ctx.dyn_sym) {
        const auto total_size = sym_count * sizeof(Elf64_Sym);
        if (!ctx.nso.isInRodata(ctx.dyn_sym->d_un.d_ptr, total_size)) {
            Panic(".dynsym must be in .rodata");
        }

        dyn_sym_index = mShdrs.size();
        auto& shdr = addSection(SHT_DYNSYM, cSectionNames[SectionType_DYN_SYM]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.dyn_sym->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.dyn_sym->d_un.d_ptr - ctx.nso.getRodataOffset();
        shdr.sh_size = total_size;
        shdr.sh_link = 0; // linked to .dynstr
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Sym);
        shdr.sh_entsize = sizeof(Elf64_Sym);

#define LINK_DYN_SYM(index) if ((index) != SHN_UNDEF) { mShdrs[index].sh_link = dyn_sym_index; }
        LINK_DYN_SYM(rel_index);
        LINK_DYN_SYM(rela_index);
        LINK_DYN_SYM(ctx.plt_rel_index);
        LINK_DYN_SYM(hash_index);
        LINK_DYN_SYM(gnu_hash_index);
#undef  LINK_DYN_SYM
    }

    // .dynstr
    if (ctx.dyn_str && ctx.dyn_str_size) {
        if (!ctx.nso.isInRodata(ctx.dyn_str->d_un.d_ptr, ctx.dyn_str_size->d_un.d_val)) {
            Panic(".dynstr must be in .rodata");
        }

        ctx.dyn_str_index = mShdrs.size();
        auto& shdr = addSection(SHT_STRTAB, cSectionNames[SectionType_DYN_STR]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = ctx.dyn_str->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.dyn_str->d_un.d_ptr - ctx.nso.getRodataOffset();
        shdr.sh_size = ctx.dyn_str_size->d_un.d_val;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(char);
        shdr.sh_entsize = 0;

        if (dyn_sym_index != SHN_UNDEF) {
            mShdrs[dyn_sym_index].sh_link = ctx.dyn_str_index;
        }
    }

    if (ctx.header->eh_frame_hdr_end < ctx.header->eh_frame_hdr_start) {
        Panic("Invalid .eh_frame_hdr range");
    }

    const auto eh_frame_hdr_size = ctx.header->eh_frame_hdr_end - ctx.header->eh_frame_hdr_start;
    const auto eh_frame_hdr_start = ctx.header_offset + ctx.header->eh_frame_hdr_start;
    if (!ctx.nso.isInRodata(eh_frame_hdr_start, eh_frame_hdr_size)) {
        Panic(".eh_frame_hdr must be in .rodata");
    }

    std::size_t max_offset = 0;
    for (const auto& shdr : mShdrs) {
        if (!ctx.nso.isInRodata(shdr.sh_addr, shdr.sh_size)) {
            continue;
        }
        max_offset = std::max(shdr.sh_addr + shdr.sh_size, max_offset);
    }

    auto exception_handling_end = std::size_t(0);
    auto eh_frame_offset = std::numeric_limits<std::size_t>::max();

    // .eh_frame_hdr
    if (eh_frame_hdr_size > 0) {
        if (eh_frame_hdr_size < sizeof(EhFrameHdr)) {
            Panic("Invalid .eh_frame_hdr range");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_EH_FRAME_HDR]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = eh_frame_hdr_start;
        shdr.sh_offset = start_offset + eh_frame_hdr_start - ctx.nso.getRodataOffset();
        shdr.sh_size = eh_frame_hdr_size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 2;
        shdr.sh_entsize = 0;

        exception_handling_end = std::max(eh_frame_hdr_start + eh_frame_hdr_size, exception_handling_end);

        const auto eh_frame_hdr = reinterpret_cast<const EhFrameHdr*>(segment_data.data() + eh_frame_hdr_start - ctx.nso.getRodataOffset());
        if (eh_frame_hdr->version != 1) {
            Panic("Invalid .eh_frame_hdr version");
        }

        // extract .eh_frame position
        if (eh_frame_hdr->eh_frame_ptr_enc != DW_EH_PE_omit) {
            switch (eh_frame_hdr->eh_frame_ptr_enc & ApplyTypeMask) {
                case DW_EH_PE_absptr: eh_frame_offset = 0; break;
                case DW_EH_PE_pcrel: eh_frame_offset = eh_frame_hdr_start + sizeof(EhFrameHdr); break;
                case DW_EH_PE_datarel: eh_frame_offset = eh_frame_hdr_start; break;
                default: Panic("Invalid pointer apply type");
            }

            const auto ptr_enc_data = std::span(segment_data).subspan(eh_frame_hdr_start - ctx.nso.getRodataOffset() + sizeof(EhFrameHdr));
            if (eh_frame_hdr->eh_frame_ptr_enc & IsSignedMask) {
                eh_frame_offset = static_cast<std::size_t>(static_cast<std::int64_t>(eh_frame_offset) + ReadSigned(eh_frame_hdr->eh_frame_ptr_enc, ptr_enc_data));
            } else {
                eh_frame_offset += ReadUnsigned(eh_frame_hdr->eh_frame_ptr_enc, ptr_enc_data);
            }
        }
    }

    auto lsda_range = std::optional<Range>{};

    // .eh_frame
    if (eh_frame_offset != std::numeric_limits<std::size_t>::max()) {
        if (!ctx.nso.isInRodata(eh_frame_offset)) {
            Panic(".eh_frame must be in .rodata");
        }

        const auto frame_size = ReadEhFrame(ctx.nso, segment_data, eh_frame_hdr_start, eh_frame_offset, lsda_range);
        if (!ctx.nso.isInRodata(eh_frame_offset, frame_size)) {
            Panic(".eh_frame must be in .rodata");
        }

        exception_handling_end = std::max(eh_frame_offset + frame_size, exception_handling_end);

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_EH_FRAME]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = eh_frame_offset;
        shdr.sh_offset = start_offset + eh_frame_offset - ctx.nso.getRodataOffset();
        shdr.sh_size = frame_size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 3;
        shdr.sh_entsize = 0;
    }

    // .gcc_except_table
    if (lsda_range) {
        if (!ctx.nso.isInRodata(lsda_range->start, lsda_range->size)) {
            Panic(".gcc_except_table must be .rodata");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_GCC_EXCEPT_TABLE]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = lsda_range->start;
        shdr.sh_offset = start_offset + lsda_range->start - ctx.nso.getRodataOffset();
        shdr.sh_size = lsda_range->size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 3;
        shdr.sh_entsize = 0;
    }

    // RO
    bool unofficial_ro_layout;
    const auto ro_end = lsda_range ? lsda_range->start : eh_frame_hdr_start;
    if (max_offset < ro_end && ctx.nso.isInRodata(max_offset)) {
        const auto ro_size = ro_end - max_offset;
        
        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_RO]);
        shdr.sh_flags = SHF_ALLOC | SHF_MERGE | SHF_STRINGS;
        shdr.sh_addr = max_offset;
        shdr.sh_offset = start_offset + max_offset - ctx.nso.getRodataOffset();
        shdr.sh_size = ro_size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 2;
        shdr.sh_entsize = 0;

        unofficial_ro_layout = false;
    } else {
        // unfortunately, a lot of unofficial NSOs do not place .rodata directly before .eh_frame_hdr
        unofficial_ro_layout = true;
    }

    const auto build_id_range = ctx.nso.findModuleIdRange();
    if (!build_id_range) {
        Panic("Failed to find .note.gnu.build-id section");
    }

    // .api_info
    if (build_id_range->size + build_id_range->start < ctx.nso.getRodataOffset() + segment_data.size()) {
        const auto start = build_id_range->size + build_id_range->start;
        const auto size = ctx.nso.getRodataOffset() + segment_data.size() - start;
        if (!ctx.nso.isInRodata(exception_handling_end, size)) {
            Panic(".api_info must be in .rodata");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_API_INFO]);
        shdr.sh_flags = SHF_ALLOC | SHF_STRINGS;
        shdr.sh_addr = start;
        shdr.sh_offset = start_offset + start - ctx.nso.getRodataOffset();
        shdr.sh_size = size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(char);
        shdr.sh_entsize = 0;
    } else if (exception_handling_end != 0 && exception_handling_end < build_id_range->start) {
        const auto size = build_id_range->start - exception_handling_end;
        if (!ctx.nso.isInRodata(exception_handling_end, size)) {
            Panic(".api_info must be in .rodata");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_API_INFO]);
        shdr.sh_flags = SHF_ALLOC | SHF_STRINGS;
        shdr.sh_addr = exception_handling_end;
        shdr.sh_offset = start_offset + exception_handling_end - ctx.nso.getRodataOffset();
        shdr.sh_size = size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(char);
        shdr.sh_entsize = 0;
    }

    // .note.gnu.build-id
    if (ctx.nso.isInRodata(build_id_range->start, build_id_range->size)) {
        auto& shdr = addSection(SHT_NOTE, cSectionNames[SectionType_GNU_BUILDID]);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = build_id_range->start;
        shdr.sh_offset = start_offset + build_id_range->start - ctx.nso.getRodataOffset();
        shdr.sh_size = build_id_range->size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Nhdr);
        shdr.sh_entsize = 0;
    } else {
        Panic(".note.gnu.build-id must be in .rodata");
    }

    if (unofficial_ro_layout) {
        std::cerr << "[WARNING] Unofficial .rodata layout detected\n";
        // TODO: how do we fill out RO for these NSOs? (we could just leave it out)
        // auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_RO]);
        // shdr.sh_flags = SHF_ALLOC | SHF_MERGE | SHF_STRINGS;
        // shdr.sh_addr = ctx.nso.getRodataOffset();
        // shdr.sh_offset = start_offset;
        // shdr.sh_size = segment_data.size();
        // shdr.sh_link = 0;
        // shdr.sh_info = 0;
        // shdr.sh_addralign = 1 << 2;
        // shdr.sh_entsize = 0;
    }
}

auto ELFBuilder::splitData(Context& ctx) -> void {
    const auto start_offset = mPhdrs[Segment_Data].p_offset;

    Range ia_range{}, fa_range{};

    // .init_array
    if (ctx.init_array && ctx.init_array_size && ctx.init_array_size->d_un.d_val > 0) {
        if (!ctx.nso.isInData(ctx.init_array->d_un.d_ptr, ctx.init_array_size->d_un.d_val)) {
            Panic(".init_array must be in .data");
        }

        auto& shdr = addSection(SHT_INIT_ARRAY, cSectionNames[SectionType_INIT_ARRAY]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = ctx.init_array->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.init_array->d_un.d_ptr - ctx.nso.getDataOffset();
        shdr.sh_size = ctx.init_array_size->d_un.d_val;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(void*);
        shdr.sh_entsize = sizeof(void*);

        ia_range.start = ctx.init_array->d_un.d_ptr;
        ia_range.size = ctx.init_array_size->d_un.d_val;
    }

    // .fini_array
    if (ctx.fini_array && ctx.fini_array_size && ctx.fini_array_size->d_un.d_val > 0) {
        if (!ctx.nso.isInData(ctx.fini_array->d_un.d_ptr, ctx.fini_array_size->d_un.d_val)) {
            Panic(".fini_array must be in .data");
        }

        auto& shdr = addSection(SHT_FINI_ARRAY, cSectionNames[SectionType_FINI_ARRAY]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = ctx.fini_array->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.fini_array->d_un.d_ptr - ctx.nso.getDataOffset();
        shdr.sh_size = ctx.fini_array_size->d_un.d_val;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(void*);
        shdr.sh_entsize = sizeof(void*);

        fa_range.start = ctx.fini_array->d_un.d_ptr;
        fa_range.size = ctx.fini_array_size->d_un.d_val;
    }

    Range dynamic_range{};

    // .dynamic
    if (const auto dyn_range = ctx.nso.findDynamicRange()) {
        if (!ctx.nso.isInData(dyn_range->start, dyn_range->size)) {
            Panic(".dynamic must be in .data");
        }

        auto& shdr = addSection(SHT_DYNAMIC, cSectionNames[SectionType_DYNAMIC]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = dyn_range->start;
        shdr.sh_offset = start_offset + dyn_range->start - ctx.nso.getDataOffset();
        shdr.sh_size = dyn_range->size;
        shdr.sh_link = ctx.dyn_str_index;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(Elf64_Dyn);
        shdr.sh_entsize = sizeof(Elf64_Dyn);

        dynamic_range = std::move(*dyn_range);
    } else {
        Panic("No .dynamic section found");
    }

    Range got_plt_range{};

    // .got.plt
    if (ctx.got_plt) {
        if (ctx.max_plt_reloc < ctx.got_plt->d_un.d_ptr) {
            Panic("Invalid .got.plt range");
        }

        const auto size = ctx.max_plt_reloc - ctx.got_plt->d_un.d_ptr;
        if (!ctx.nso.isInData(ctx.got_plt->d_un.d_ptr, size)) {
            Panic(".got.plt must be in .data");
        }

        const auto index = mShdrs.size();
        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_GOT_PLT]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = ctx.got_plt->d_un.d_ptr;
        shdr.sh_offset = start_offset + ctx.got_plt->d_un.d_ptr - ctx.nso.getDataOffset();
        shdr.sh_size = size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(void*);
        shdr.sh_entsize = sizeof(void*);

        if (ctx.plt_rel_index != SHN_UNDEF) {
            mShdrs[ctx.plt_rel_index].sh_flags |= SHF_INFO_LINK;
            mShdrs[ctx.plt_rel_index].sh_info = index;
        }

        got_plt_range.start = ctx.got_plt->d_un.d_ptr;
        got_plt_range.size = size;
    }

    bool has_got = false;
    Range got_range{};

    // .got
    if (ctx.libnx_extension) {
        if (ctx.libnx_extension->got_end < ctx.libnx_extension->got_start) {
            Panic("Invalid .got range");
        }

        const auto size = ctx.libnx_extension->got_end - ctx.libnx_extension->got_start;
        if (!ctx.nso.isInData(ctx.libnx_extension->got_start, size)) {
            Panic(".got must be in .data");
        }

        auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_GOT]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = ctx.libnx_extension->got_start;
        shdr.sh_offset = start_offset + ctx.libnx_extension->got_start - ctx.nso.getDataOffset();
        shdr.sh_size = size;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = alignof(void*);
        shdr.sh_entsize = sizeof(void*);

        has_got = true;
        got_range.start = ctx.libnx_extension->got_start;
        got_range.size = size;
    } else if (ctx.rocrt_version == 0) {
        const auto got_start = ctx.got_plt ? got_plt_range.start + got_plt_range.size : dynamic_range.start + dynamic_range.size;
        auto got_end = got_start;

        if (ctx.nso.isInData(got_end, sizeof(void*))) {
            const auto value = *reinterpret_cast<const std::uint64_t*>(ctx.nso.getData().data() + got_end - ctx.nso.getDataOffset());
            if (value == dynamic_range.start) {
                got_end += sizeof(void*); 
            }
        }

        if (ctx.init_array && ctx.init_array_size) {
            while (ctx.relocations.contains(got_end) && got_end < ia_range.start && ctx.nso.isInData(got_end)) {
                got_end += sizeof(void*);
            }
        } else {
            // FIXME: if there is no .init_array, this will run into .atexit
            while (ctx.relocations.contains(got_end) && ctx.nso.isInData(got_end)) {
                got_end += sizeof(void*);
            }
        }

        if (got_end - got_start > 0) {
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_GOT]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = got_start;
            shdr.sh_offset = start_offset + got_start - ctx.nso.getDataOffset();
            shdr.sh_size = got_end - got_start;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = alignof(void*);
            shdr.sh_entsize = sizeof(void*);

            has_got = true;
            got_range.start = got_start;
            got_range.size = got_end - got_start;
        }
    } else {
        auto got_start = dynamic_range.start + dynamic_range.size;
        std::size_t got_end;
        if (ctx.got_plt) {
            if (got_plt_range.start + got_plt_range.size < dynamic_range.start + dynamic_range.size) {
                // assume this is an unofficial NSO where .got runs until .dynamic
                // this applies to oss-rtld, exlaunch, skyline
                got_start = got_plt_range.start + got_plt_range.size;
                got_end = dynamic_range.start;
            } else {
                got_end = got_plt_range.start;
            }
        } else {
            got_end = got_start;

            if (ctx.nso.isInData(got_end, sizeof(void*))) {
                const auto value = *reinterpret_cast<const std::uint64_t*>(ctx.nso.getData().data() + got_end - ctx.nso.getDataOffset());
                if (value == dynamic_range.start) {
                    got_end += sizeof(void*); 
                }
            }

            // search until we reach the end of valid relocations
            // this should be fine since newer versions no longer have .atexit afaict
            while (ctx.relocations.contains(got_end) && ctx.nso.isInData(got_end)) {
                got_end += sizeof(void*);
            }
        }

        if (got_end > got_start) {
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_GOT]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = got_start;
            shdr.sh_offset = start_offset + got_start - ctx.nso.getDataOffset();
            shdr.sh_size = got_end - got_start;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = alignof(void*);
            shdr.sh_entsize = sizeof(void*);

            has_got = true;
            got_range.start = got_start;
            got_range.size = got_end - got_start;
        }
    }

    Range atexit_range{};

    // .atexit
    if (ctx.rocrt_version == 0) {
        auto min_allowed = std::numeric_limits<std::size_t>::min();
        // we don't bother to check if the sections exists bc if they don't, the range is zero anyways
        min_allowed = std::max(static_cast<std::size_t>(ia_range.start + ia_range.size), min_allowed);
        min_allowed = std::max(static_cast<std::size_t>(fa_range.start + fa_range.size), min_allowed);
        min_allowed = std::max(static_cast<std::size_t>(got_plt_range.start + got_plt_range.size), min_allowed);
        min_allowed = std::max(static_cast<std::size_t>(got_range.start + got_range.size), min_allowed);

        auto min_reloc = std::numeric_limits<std::size_t>::max();
        auto max_reloc = std::numeric_limits<std::size_t>::min();
        for (const auto& reloc : ctx.relocations) {
            if (reloc < min_allowed) {
                continue;
            }

            min_reloc = std::min(reloc, min_reloc);
            max_reloc = std::max(reloc + sizeof(void*), max_reloc);
        }

        if (max_reloc > min_reloc) {
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_ATEXIT]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = min_reloc;
            shdr.sh_offset = start_offset + min_reloc - ctx.nso.getDataOffset();
            shdr.sh_size = max_reloc - min_reloc;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = alignof(void*);
            shdr.sh_entsize = sizeof(void*);

            atexit_range.start = min_reloc;
            atexit_range.size = max_reloc - min_reloc;
        }
    }

    // .data.rel.ro
    if (ctx.rocrt_version == 1) {
        std::size_t max_allowed = 0;
        max_allowed = std::max(static_cast<std::size_t>(ia_range.start + ia_range.size), max_allowed);
        max_allowed = std::max(static_cast<std::size_t>(fa_range.start + fa_range.size), max_allowed);
        max_allowed = std::max(static_cast<std::size_t>(got_plt_range.start + got_plt_range.size), max_allowed);
        max_allowed = std::max(static_cast<std::size_t>(got_range.start + got_range.size), max_allowed);
        auto min_reloc = std::numeric_limits<std::size_t>::max();
        auto max_reloc = std::numeric_limits<std::size_t>::min();
        for (const auto& reloc : ctx.relocations) {
            if (reloc == 0 || reloc >= max_allowed) {
                continue;
            }

            // we don't bother to check if the sections exists bc if they don't, the range is zero anyways
            if (ia_range.contains(reloc) ||
                fa_range.contains(reloc) ||
                got_plt_range.contains(reloc) ||
                got_range.contains(reloc) ||
                atexit_range.contains(reloc)
            ) {
                continue;
            }

            min_reloc = std::min(reloc, min_reloc);
            max_reloc = std::max(reloc + sizeof(void*), max_reloc);
        }

        if (max_reloc > min_reloc) {
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_DATA_REL_RO]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = min_reloc;
            shdr.sh_offset = start_offset + min_reloc - ctx.nso.getDataOffset();
            shdr.sh_size = max_reloc - min_reloc;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = alignof(void*);
            shdr.sh_entsize = 0;
        }
    }

    // RW
    if (ctx.rocrt_version == 0) {
        // RW is the first portion of .data
        auto min_offset = std::numeric_limits<std::size_t>::max();
        for (const auto& shdr : mShdrs) {
            if (!ctx.nso.isInData(shdr.sh_addr)) {
                continue;
            }
            min_offset = std::min(shdr.sh_addr, min_offset);
        }

        if (min_offset != std::numeric_limits<std::size_t>::max() && min_offset > ctx.nso.getDataOffset()) {
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_RW]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = ctx.nso.getDataOffset();
            shdr.sh_offset = start_offset;
            shdr.sh_size = min_offset - ctx.nso.getDataOffset();
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1 << 2;
            shdr.sh_entsize = 0;
        }
    } else {
        // RW is the last portion of .data
        std::size_t max_offset = 0;
        for (const auto& shdr : mShdrs) {
            if (!ctx.nso.isInData(shdr.sh_addr, shdr.sh_size)) {
                continue;
            }
            max_offset = std::max(shdr.sh_addr + shdr.sh_size, max_offset);
        }

        const auto rw_start = (max_offset + cSegmentAlignment - 1) / cSegmentAlignment * cSegmentAlignment;

        // .rocrt.align.relroend
        if (rw_start != max_offset) {
            const auto offset = max_offset - ctx.nso.getDataOffset();
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_ROCRT_ALIGN_RELROEND]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = max_offset;
            shdr.sh_offset = start_offset + offset;
            shdr.sh_size = rw_start - max_offset;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1 << 2;
            shdr.sh_entsize = 0;
        }

        if (ctx.nso.isInData(rw_start)) {
            const auto data_offset = rw_start - ctx.nso.getDataOffset();
            auto& shdr = addSection(SHT_PROGBITS, cSectionNames[SectionType_RW]);
            shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
            shdr.sh_addr = rw_start;
            shdr.sh_offset = start_offset + data_offset;
            shdr.sh_size = ctx.nso.getData().size() - data_offset;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1 << 2;
            shdr.sh_entsize = 0;
        }
    }
}

auto ELFBuilder::splitBss(Context& ctx) -> void {
    // ZI
    if (ctx.nso.getBssSize() > 0) {
        auto& shdr = addSection(SHT_NOBITS, cSectionNames[SectionType_ZI]);
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_addr = ctx.nso.getBssOffset();
        shdr.sh_offset = mPhdrs[Segment_Data].p_offset + mPhdrs[Segment_Data].p_filesz;
        shdr.sh_size = ctx.nso.getBssSize();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1 << 2;
        shdr.sh_entsize = 0;
    }
}

auto ELFBuilder::splitSections(const NSOFile& nso) -> void {
    auto ctx = Context{
        .nso = nso
    };

    ctx.header = ctx.nso.getModuleHeader(std::addressof(ctx.header_offset));

    for (const auto& dyn : ctx.nso.getDynamic()) {
        switch (dyn.d_tag) {
            case DT_REL: ctx.rel = std::addressof(dyn); break;
            case DT_RELSZ: ctx.rel_size = std::addressof(dyn); break;
            case DT_RELA: ctx.rela = std::addressof(dyn); break;
            case DT_RELASZ: ctx.rela_size = std::addressof(dyn); break;
            case DT_JMPREL: ctx.plt_rel = std::addressof(dyn); break;
            case DT_PLTRELSZ: ctx.plt_rel_size = std::addressof(dyn); break;
            case DT_PLTREL: ctx.plt_rel_type = std::addressof(dyn); break;
            case DT_RELR: ctx.relr = std::addressof(dyn); break;
            case DT_RELRSZ: ctx.relr_size = std::addressof(dyn); break;
            case DT_HASH: ctx.hash = std::addressof(dyn); break;
            case DT_GNU_HASH: ctx.gnu_hash = std::addressof(dyn); break;
            case DT_SYMTAB: ctx.dyn_sym = std::addressof(dyn); break;
            case DT_STRTAB: ctx.dyn_str = std::addressof(dyn); break;
            case DT_STRSZ: ctx.dyn_str_size = std::addressof(dyn); break;
            case DT_INIT_ARRAY: ctx.init_array = std::addressof(dyn); break;
            case DT_INIT_ARRAYSZ: ctx.init_array_size = std::addressof(dyn); break;
            case DT_FINI_ARRAY: ctx.fini_array = std::addressof(dyn); break;
            case DT_FINI_ARRAYSZ: ctx.fini_array_size = std::addressof(dyn); break;
            case DT_PLTGOT: ctx.got_plt = std::addressof(dyn); break;
        }
    }

    splitText(ctx);
    splitRodata(ctx);
    splitData(ctx);
    splitBss(ctx);
}

auto ELFBuilder::build(const NSOFile& nso) -> void {
    std::size_t current_file_offset = (sizeof(mHeader) + cProgramAlign - 1) / cProgramAlign * cProgramAlign;
    std::size_t current_virt_offset = 0;
    std::size_t current_phys_offset = 0;
    for (std::uint32_t segment = Segment_Start; segment < Segment_Count; ++segment) {
        const auto& segment_data = nso.getSegment(segment);
        auto& phdr = mPhdrs[segment];
        phdr.p_type = PT_LOAD;
        phdr.p_offset = current_file_offset;
        phdr.p_vaddr = current_virt_offset;
        phdr.p_paddr = current_phys_offset;
        phdr.p_filesz = segment_data.size();
        phdr.p_memsz = segment_data.size();
        phdr.p_align = cProgramAlign;
        switch (segment) {
            case Segment_Text:
                if (nso.isFlagSet(ExecuteOnlyMemory)) {
                    phdr.p_flags = PF_X;
                } else {
                    phdr.p_flags = PF_R | PF_X;
                }
                break;
            case Segment_Ro:
                phdr.p_flags = PF_R;
                break;
            case Segment_Data:
                phdr.p_flags = PF_R | PF_W;
                phdr.p_memsz += nso.getBssSize();
                break;
        }

        addProgBits(segment_data, cProgramAlign);
        current_file_offset = (current_file_offset + phdr.p_filesz + cProgramAlign - 1) / cProgramAlign * cProgramAlign;
        current_virt_offset += (phdr.p_memsz + cSegmentAlignment - 1) / cSegmentAlignment * cSegmentAlignment;
        current_phys_offset += (phdr.p_memsz + cSegmentAlignment - 1) / cSegmentAlignment * cSegmentAlignment;
    }

    const auto dynamic = nso.findDynamicRange();
    if (!dynamic) {
        Panic("Failed to find .dynamic");
    }

    if (!nso.isInData(dynamic->start, dynamic->size)) {
        Panic(".dynamic must be in .data");
    }

    mPhdrs[cDynamicIndex].p_type = PT_DYNAMIC;
    mPhdrs[cDynamicIndex].p_flags = PF_R | PF_W;
    mPhdrs[cDynamicIndex].p_offset = mPhdrs[Segment_Data].p_offset + dynamic->start - nso.getDataOffset();
    mPhdrs[cDynamicIndex].p_vaddr = dynamic->start;
    mPhdrs[cDynamicIndex].p_paddr = dynamic->start;
    mPhdrs[cDynamicIndex].p_filesz = dynamic->size;
    mPhdrs[cDynamicIndex].p_memsz = dynamic->size;
    mPhdrs[cDynamicIndex].p_align = cDynamicAlign;

    splitSections(nso);

    std::size_t shdr_offset = sizeof(mHeader) + sizeof(Elf64_Phdr) * mPhdrs.size();
    for (const auto& bits : mProgBits) {
        shdr_offset = (shdr_offset + bits.align - 1) / bits.align * bits.align + bits.data.size();
    }

    auto& shdr = addSection(SHT_STRTAB, ".shstrtab");
    shdr.sh_flags = 0;
    shdr.sh_offset = shdr_offset;
    shdr.sh_size = mSectionNames.size();
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = alignof(char);
    shdr.sh_entsize = 0;

    shdr_offset += mSectionNames.size();

    mHeader.e_shoff = (shdr_offset + 8 - 1) / 8 * 8;
    mHeader.e_shnum = mShdrs.size();
    mHeader.e_shstrndx = mShdrs.size() - 1; // string table is last
}

auto ELFBuilder::write(std::string_view path) const -> void {
    auto file = std::ofstream(std::string(path), std::ios::binary);

    file.write(reinterpret_cast<const char*>(std::addressof(mHeader)), sizeof(mHeader));

    file.write(reinterpret_cast<const char*>(mPhdrs.data()), mPhdrs.size() * sizeof(Elf64_Phdr));
    
    for (const auto& bits : mProgBits) {
        file.seekp((static_cast<std::size_t>(file.tellp()) + bits.align - 1) / bits.align * bits.align);
        file.write(reinterpret_cast<const char*>(bits.data.data()), bits.data.size());
    }

    file.write(mSectionNames.data(), mSectionNames.size());

    file.seekp((static_cast<std::size_t>(file.tellp()) + 8 - 1) / 8 * 8);
    file.write(reinterpret_cast<const char*>(mShdrs.data()), mShdrs.size() * sizeof(Elf64_Shdr));
}

auto NSOFile::saveELF(std::string_view path) -> NSOFile& {
    auto builder = ELFBuilder();
    builder.build(*this);
    builder.write(path.empty() ? mName + ".nss" : path);
    return *this;
}