#include "elf.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
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
static constexpr const std::size_t cSectionAlignment = 0x1000;

using Hash = std::array<std::uint8_t, 0x20>;
using ModuleId = std::array<std::uint8_t, 0x20>;

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
    union {
        struct {
            Hash text_hash;
            Hash ro_hash;
            Hash data_hash;
        };
        Hash section_hashes[Section_Count];
    };
};
static_assert(sizeof(NSOHeader) == 0x100);

struct RocrtInit {
    std::uint32_t entry;
    std::uint32_t rocrt_info_offset;
    // new versions only
    std::uint32_t rocrt_version_offset;
};

struct ModuleHeader {
    std::uint32_t signature;
    std::int32_t dynamic_offset;
    std::int32_t bss_start;
    std::int32_t bss_end;
    std::int32_t eh_frame_hdr_start;
    std::int32_t eh_frame_hdr_end;
    std::int32_t ro_module_offset;
    // new versions only
    std::int32_t relro_start;
    std::int32_t full_relro_end;
    std::int32_t nx_debuglink_start;
    std::int32_t nx_debuglink_end;
    std::int32_t gnu_buildid_start;
    std::int32_t gnu_buildid_end;
};

struct RocrtVersion {
    std::uint32_t sdk_major;
    std::uint32_t sdk_minor;
    std::uint32_t sdk_micro;
};

static constexpr const std::size_t cMinimumRocrtInitSize = 0x8;
static constexpr const std::size_t cMinimumModuleHeaderSize = 0x1c;

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
    std::uint32_t sym_offset;   // the index exported symbols start at (before this are imported symbols)
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

class NSOFile {
public:
    NSOFile() = default;

    auto setName(std::string_view name) -> NSOFile& {
        mName = name;
        return *this;
    }

    auto setFlag(Flags flag) -> NSOFile& {
        mFlags |= flag;
        return *this;
    }

    auto setFlag(Flags flag, bool value) -> NSOFile& {
        if (value) {
            return setFlag(flag);
        } else {
            return unsetFlag(flag);
        }
    }

    auto unsetFlag(Flags flag) -> NSOFile& {
        mFlags &= ~flag;
        return *this;
    }

    auto unsetFlag(Flags flag, bool value) -> NSOFile& {
        if (value) {
            return unsetFlag(flag);
        } else {
            return setFlag(flag);
        }
    }

    [[nodiscard]] auto isFlagSet(Flags flag) const -> bool {
        return (mFlags & flag) != 0;
    }

    [[nodiscard]] auto getFlag() const -> std::uint32_t {
        return mFlags;
    }

    [[nodiscard]] auto getModuleId() const -> const ModuleId& {
        return mModuleId;
    }

    [[nodiscard]] auto getSection(std::uint32_t section) const -> const std::vector<std::uint8_t>& {
        return mSections.at(section);
    }

    [[nodiscard]] auto getText() const -> const std::vector<std::uint8_t>& {
        return getSection(Section_Text);
    }

    [[nodiscard]] auto getRodata() const -> const std::vector<std::uint8_t>& {
        return getSection(Section_Ro);
    }

    [[nodiscard]] auto getData() const -> const std::vector<std::uint8_t>& {
        return getSection(Section_Data);
    }

    [[nodiscard]] auto getBssSize() const -> std::size_t {
        return mBssSize;
    }

    [[nodiscard]] auto getTextOffset() const -> std::size_t {
        return 0;
    }

    [[nodiscard]] auto getRodataOffset() const -> std::size_t {
        return (getTextOffset() + getSection(Section_Text).size() + cSectionAlignment- 1) / cSectionAlignment* cSectionAlignment;
    }

    [[nodiscard]] auto getDataOffset() const -> std::size_t {
        return (getRodataOffset() + getSection(Section_Ro).size() + cSectionAlignment - 1) / cSectionAlignment * cSectionAlignment;
    }

    [[nodiscard]] auto getBssOffset() const -> std::size_t {
        return getDataOffset() + getSection(Section_Data).size();
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

    auto loadNSO(std::string_view path, bool skip_validation = false) -> NSOFile&;
    auto loadELF(std::string_view path) -> NSOFile&;

    auto saveNSO(std::string_view path, const std::optional<std::string_view>& name = std::nullopt, const std::optional<ModuleId>& module_id = std::nullopt) -> NSOFile&;
    auto saveELF(std::string_view path) -> NSOFile&;

    [[nodiscard]] auto getRocrtInit() const -> const RocrtInit*;
    [[nodiscard]] auto getModuleHeader(std::size_t* offset) const -> const ModuleHeader*;
    [[nodiscard]] auto getDynamic() const -> std::span<const Elf64_Dyn>;

    [[nodiscard]] auto findDynamicRange() const -> std::optional<Range>;
    [[nodiscard]] auto findDynSymRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range>;
    [[nodiscard]] auto findDynStrRange(std::span<const Elf64_Dyn> dynamic) const -> std::optional<Range>;
    [[nodiscard]] auto findModuleNameRange() const -> std::optional<Range>;
    [[nodiscard]] auto findModuleIdRange() const -> std::optional<Range>;

private:
    auto setSection(std::uint32_t section, std::span<const std::uint8_t> data) -> NSOFile& {
        mSections.at(section).assign(data.begin(), data.end());
        return *this;
    }

    [[nodiscard]] auto getSection(std::uint32_t section) -> std::vector<std::uint8_t>& {
        return mSections.at(section);
    }

    [[nodiscard]] auto getText() -> std::vector<std::uint8_t>& {
        return getSection(Section_Text);
    }

    [[nodiscard]] auto getRodata() -> std::vector<std::uint8_t>& {
        return getSection(Section_Ro);
    }

    [[nodiscard]] auto getData() -> std::vector<std::uint8_t>& {
        return getSection(Section_Data);
    }

    [[nodiscard]] auto getName() const -> std::string_view {
        return mName;
    }

    auto setBssSize(std::size_t size) -> NSOFile& {
        mBssSize = size;
        return *this;
    }

    auto setModuleId(const ModuleId& id) -> NSOFile&;

    auto setModuleNameFromRodata() -> void;
    auto setModuleIdFromRodata() -> void;

    std::array<std::vector<std::uint8_t>, Section_Count> mSections;
    std::string mName;
    std::size_t mBssSize = 0;
    std::uint32_t mFlags = 0;
    ModuleId mModuleId = {};
    Range mDynStr = {};
    Range mDynSym = {};
};

inline auto GetRocrtVersion(const RocrtInit* rocrt) -> std::uint32_t{
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