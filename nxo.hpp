#include "elf.h"

#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

template <typename... Ts>
[[noreturn]] auto Panic(Ts&&... args) -> void {
    (std::cerr << ... << std::forward<Ts>(args)) << "\n";
    std::exit(1);
}

enum SegmentType : std::uint32_t {
    Segment_Text    = 0,
    Segment_Ro      = 1,
    Segment_Data    = 2,

    Segment_Count,
    Segment_Start   = Segment_Text,
};

static constexpr char NSO_SIGNATURE[4] = { 'N', 'S', 'O', '0' };
static constexpr char NRO_SIGNATURE[4] = { 'N', 'R', 'O', '0' };
static constexpr std::size_t cSegmentAlignment = 0x1000;

struct ModuleHeaderLocation {
    std::uint32_t entry;
    std::uint32_t rocrt_info_offset;
    // new versions only
    std::uint32_t rocrt_version_offset;
};

struct ModuleHeader {
    std::uint32_t signature;
    std::uint32_t dynamic_offset;
    std::uint32_t bss_start;
    std::uint32_t bss_end;
    std::uint32_t eh_frame_hdr_start;
    std::uint32_t eh_frame_hdr_end;
    std::uint32_t ro_module_offset;
    // new versions only
    std::uint32_t relro_start;
    std::uint32_t full_relro_end;
    std::int32_t nx_debuglink_start;
    std::int32_t nx_debuglink_end;
    std::int32_t gnu_buildid_start;
    std::int32_t gnu_buildid_end;
};

struct RocrtHeader {
    ModuleHeaderLocation header_location;
    std::uint32_t reserved;
};

struct RocrtVersion {
    std::uint32_t sdk_major;
    std::uint32_t sdk_minor;
    std::uint32_t sdk_micro;
};

static constexpr std::size_t cMinimumModuleHeaderLocationSize = 0x8;
static constexpr std::size_t cMinimumModuleHeaderSize = 0x1c;

struct NxDebuglink {
    std::uint32_t version;
    std::uint32_t name_size;
    // char name[name_size];
};

struct ElfHashTable {
    std::uint32_t nbucket;
    std::uint32_t nchain;
    // std::uint32_t buckets[nbucket];
    // std::uint32_t chain[nchain];
};

struct GnuHashTable {
    std::uint32_t nbucket;
    std::uint32_t sym_offset;   // the index exported symbols start at (before this are imported/hidden symbols)
    std::uint32_t bloom_size;
    std::uint32_t bloom_shift;
    // std::uint64_t bloom[bloom_size];
    // std::uint32_t buckets[nbucket];
    // std::uint32_t chain[]; // until bit 0 is set
};

struct Range {
    std::uint32_t start;
    std::uint32_t size;

    constexpr auto contains(std::size_t value) const -> bool {
        return value >= static_cast<std::size_t>(start) && value < static_cast<std::size_t>(start + size);
    }
};

using Hash = std::array<std::uint8_t, 0x20>;
using ModuleId = std::array<std::uint8_t, 0x20>;

inline constexpr auto CheckSignature(const char(&value)[4], const char(&expected)[4]) -> bool {
    return value[0] == expected[0] && value[1] == expected[1] && value[2] == expected[2] && value[3] == expected[3];
}

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
    ModuleId module_id;
    std::uint32_t text_compressed_size;
    std::uint32_t ro_compressed_size;
    std::uint32_t data_compressed_size;
    std::uint8_t reserved1[0x24];
    std::uint32_t dyn_str_offset;
    std::uint32_t dyn_str_size;
    std::uint32_t dyn_sym_offset;
    std::uint32_t dyn_sym_size;
    Hash segment_hashes[Segment_Count];
};
static_assert(sizeof(NSOHeader) == 0x100);

struct NROHeader {
    RocrtHeader header;
    char signature[4];
    std::uint32_t version;
    std::uint32_t size;
    std::uint32_t flags;
    std::uint32_t text_offset;
    std::uint32_t text_size;
    std::uint32_t ro_offset;
    std::uint32_t ro_size;
    std::uint32_t rw_offset;
    std::uint32_t rw_size;
    std::uint32_t bss_size;
    std::uint32_t reserved0;
    ModuleId module_id;
    std::uint32_t dso_handle_offset;
    std::uint32_t reserved1;
    std::uint32_t api_info_offset;
    std::uint32_t api_info_size;
    std::uint32_t dyn_str_offset;
    std::uint32_t dyn_str_size;
    std::uint32_t dyn_sym_offset;
    std::uint32_t dyn_sym_size;
};
static_assert(sizeof(NROHeader) == 0x80);

class NXOFile {
public:
    enum NSOFlags {
        TextCompress        = 1 << 0,
        RoCompress          = 1 << 1,
        DataCompress        = 1 << 2,
        TextHash            = 1 << 3,
        RoHash              = 1 << 4,
        DataHash            = 1 << 5,
        ExecuteOnlyMemory   = 1 << 6,
        UseZbicCompression  = 1 << 7,
    };

    enum NROFlags {
        HeaderSection       = 1 << 0,
    };

    NXOFile() = default;

    auto setName(std::string_view name) -> NXOFile& {
        mName = name;
        return *this;
    }

    auto setFlag(NSOFlags flag) -> NXOFile& {
        mNSOFlags |= flag;
        return *this;
    }

    auto setFlag(NSOFlags flag, bool value) -> NXOFile& {
        if (value) {
            return setFlag(flag);
        } else {
            return unsetFlag(flag);
        }
    }

    auto unsetFlag(NSOFlags flag) -> NXOFile& {
        mNSOFlags &= ~flag;
        return *this;
    }

    auto unsetFlag(NSOFlags flag, bool value) -> NXOFile& {
        if (value) {
            return unsetFlag(flag);
        } else {
            return setFlag(flag);
        }
    }

    [[nodiscard]] auto isFlagSet(NSOFlags flag) const -> bool {
        return (mNSOFlags & flag) != 0;
    }

    [[nodiscard]] auto getNSOFlags() const -> std::uint32_t {
        return mNSOFlags;
    }

    
    auto setFlag(NROFlags flag) -> NXOFile& {
        mNROFlags |= flag;
        return *this;
    }

    auto setFlag(NROFlags flag, bool value) -> NXOFile& {
        if (value) {
            return setFlag(flag);
        } else {
            return unsetFlag(flag);
        }
    }

    auto unsetFlag(NROFlags flag) -> NXOFile& {
        mNROFlags &= ~flag;
        return *this;
    }

    auto unsetFlag(NROFlags flag, bool value) -> NXOFile& {
        if (value) {
            return unsetFlag(flag);
        } else {
            return setFlag(flag);
        }
    }

    [[nodiscard]] auto isFlagSet(NROFlags flag) const -> bool {
        return (mNROFlags & flag) != 0;
    }

    [[nodiscard]] auto getNROFlags() const -> std::uint32_t {
        return mNROFlags;
    }

    [[nodiscard]] auto getModuleId() const -> const ModuleId& {
        return mModuleId;
    }

    [[nodiscard]] auto getSegment(std::uint32_t segment) const -> const std::vector<std::uint8_t>& {
        return mSegments.at(segment);
    }

    [[nodiscard]] auto getText() const -> const std::vector<std::uint8_t>& {
        return getSegment(Segment_Text);
    }

    [[nodiscard]] auto getRodata() const -> const std::vector<std::uint8_t>& {
        return getSegment(Segment_Ro);
    }

    [[nodiscard]] auto getData() const -> const std::vector<std::uint8_t>& {
        return getSegment(Segment_Data);
    }

    [[nodiscard]] auto getBssSize() const -> std::size_t {
        return mBssSize;
    }

    [[nodiscard]] auto getTextOffset() const -> std::size_t {
        return 0;
    }

    [[nodiscard]] auto getRodataOffset() const -> std::size_t {
        return (getTextOffset() + getText().size() + cSegmentAlignment- 1) / cSegmentAlignment* cSegmentAlignment;
    }

    [[nodiscard]] auto getDataOffset() const -> std::size_t {
        return (getRodataOffset() + getRodata().size() + cSegmentAlignment - 1) / cSegmentAlignment * cSegmentAlignment;
    }

    [[nodiscard]] auto getBssOffset() const -> std::size_t {
        return getDataOffset() + getData().size();
    }

    [[nodiscard]] auto isInText(std::size_t offset) const -> bool {
        return getTextOffset() <= offset && offset < getRodataOffset();
    }

    [[nodiscard]] auto isInText(std::size_t offset, std::size_t size) const -> bool {
        return getTextOffset() <= offset && offset + size <= getRodataOffset();
    }

    [[nodiscard]] auto isInRodata(std::size_t offset) const -> bool {
        return getRodataOffset() <= offset && offset < getDataOffset();
    }

    [[nodiscard]] auto isInRodata(std::size_t offset, std::size_t size) const -> bool {
        return getRodataOffset() <= offset && offset + size <= getDataOffset();
    }

    [[nodiscard]] auto isInData(std::size_t offset) const -> bool {
        return getDataOffset() <= offset && offset < getBssOffset();
    }

    [[nodiscard]] auto isInData(std::size_t offset, std::size_t size) const -> bool {
        return getDataOffset() <= offset && offset + size <= getBssOffset();
    }

    auto loadNSO(std::string_view path, bool skip_validation = false) -> NXOFile&;
    auto loadNRO(std::string_view path) -> NXOFile&;
    auto loadELF(std::string_view path) -> NXOFile&;

    auto saveNSO(std::string_view path, const std::optional<std::string_view>& name = std::nullopt, const std::optional<ModuleId>& module_id = std::nullopt) -> NXOFile&;
    auto saveNRO(std::string_view path, const std::optional<ModuleId>& module_id = std::nullopt) -> NXOFile&;
    auto saveELF(std::string_view path) -> NXOFile&;

    [[nodiscard]] auto getModuleHeaderLocation() const -> const ModuleHeaderLocation*;
    [[nodiscard]] auto getModuleHeader(std::size_t* offset) const -> const ModuleHeader*;
    [[nodiscard]] auto getDynamic() const -> std::span<const Elf64_Dyn>;

    [[nodiscard]] auto findDynamicRange() const -> std::optional<Range>;
    [[nodiscard]] auto findDynSymRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range>;
    [[nodiscard]] auto findDynStrRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range>;
    [[nodiscard]] auto findModuleNameRange() const -> std::optional<Range>;
    [[nodiscard]] auto findModuleIdRange() const -> std::optional<Range>;
    [[nodiscard]] auto findApiInfoRange() const -> std::optional<Range>;
    [[nodiscard]] auto findEhFrame() const -> std::optional<std::size_t>;

    auto readEhFrame(std::size_t eh_frame_start, std::optional<Range>* lsda_range) const -> std::size_t;

    [[nodiscard]] auto isNSO() const -> bool { return !isNRO(); }
    [[nodiscard]] auto isNRO() const -> bool;

private:
    auto setSegment(std::uint32_t segment, std::span<const std::uint8_t> data) -> NXOFile& {
        mSegments.at(segment).assign(data.begin(), data.end());
        return *this;
    }

    [[nodiscard]] auto getSegment(std::uint32_t segment) -> std::vector<std::uint8_t>& {
        return mSegments.at(segment);
    }

    [[nodiscard]] auto getText() -> std::vector<std::uint8_t>& {
        return getSegment(Segment_Text);
    }

    [[nodiscard]] auto getRodata() -> std::vector<std::uint8_t>& {
        return getSegment(Segment_Ro);
    }

    [[nodiscard]] auto getData() -> std::vector<std::uint8_t>& {
        return getSegment(Segment_Data);
    }

    [[nodiscard]] auto getName() const -> std::string_view {
        return mName;
    }

    auto setBssSize(std::size_t size) -> NXOFile& {
        mBssSize = size;
        return *this;
    }

    auto setModuleId(const ModuleId& id) -> NXOFile&;

    auto setModuleNameFromRodata() -> void;
    auto setModuleIdFromRodata() -> void;

    auto findDsoHandle() const -> std::optional<std::uint32_t>;

    std::array<std::vector<std::uint8_t>, Segment_Count> mSegments;
    std::string mName;
    std::size_t mBssSize = 0;
    std::uint32_t mNSOFlags = 0;
    std::uint32_t mNROFlags = 0;
    ModuleId mModuleId = {};
    Range mDynStr = {};
    Range mDynSym = {};
};

inline auto GetRocrtVersion(const ModuleHeaderLocation* rocrt) -> std::uint32_t {
    switch (rocrt->entry) {
        // rtld entrypoints
        case 0xea000000: // b #0x8 (arm)
            return 0;
        case 0xea000001: // b #0xc (arm)
            return 1;
        case 0xff000001: // ???
            return 1;
        case 0x14000002: // b #0x8 (aarch64)
            return 0;
        case 0x14000003: // b #0xc (aarch64)
            return 1;

        // application entrypoints
        case 0:
            return 0;
        case 1:
            return 1;
        
        default:
            return 1;
    }
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

inline auto GetLEB128Size(std::span<const std::uint8_t> data) -> std::size_t {
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

inline auto GetSize(Encoding enc, std::span<const std::uint8_t> data) -> std::size_t {
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
auto ReadLEB128(std::span<const std::uint8_t> data) -> decltype(auto) {
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
        constexpr auto nbits = sizeof(ResultT) * CHAR_BIT;
        if ((shift < nbits) && ((byte & 0x40) != 0)) {
            result = (result << (nbits - shift)) >> (nbits - shift);
        }
    }

    return result;
}

inline auto ReadSigned(Encoding enc, std::span<const std::uint8_t> data) -> std::int64_t {
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

inline auto ReadUnsigned(Encoding enc, std::span<const std::uint8_t> data) -> std::uint64_t {
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