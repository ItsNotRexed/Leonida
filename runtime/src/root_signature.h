#pragma once

// Serialized D3D12 root signatures (the RTS0 format D3D12SerializeVersionedRootSignature writes, either as a DXBC
// container or as a bare RTS0 part) and the user-data layout the translated shaders read (docs/d3d12_vulkan.md
// section 3.5): root parameters in order, 32-bit constants one dword each, root CBV/SRV/UAV and descriptor tables
// two dwords (a 64-bit console VA). That default mapping is an assumption until the game's shaders are checked
// against it; the flags' Xbox high byte (0x03000000 measured) is kept, not interpreted. No Windows dependency.

#include "shader_library.h"  // dxbc_part

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace leonida {

// D3D12_ROOT_PARAMETER_TYPE.
namespace root_parameter {
inline constexpr std::uint32_t descriptor_table = 0;
inline constexpr std::uint32_t constants = 1;
inline constexpr std::uint32_t cbv = 2;
inline constexpr std::uint32_t srv = 3;
inline constexpr std::uint32_t uav = 4;
} // namespace root_parameter

// The user-data block the translated shaders take as push constants s0..s31.
inline constexpr std::uint32_t user_data_dwords = 32;

struct DescriptorRange {
    std::uint32_t type;  // D3D12_DESCRIPTOR_RANGE_TYPE
    std::uint32_t count;
    std::uint32_t base_register;
    std::uint32_t space;
    std::uint32_t flags;  // 1.1 only
    std::uint32_t table_offset;
};

struct RootParameter {
    std::uint32_t type;
    std::uint32_t visibility;     // D3D12_SHADER_VISIBILITY
    std::uint32_t shader_register;
    std::uint32_t space;
    std::uint32_t constant_count;  // constants only
    std::uint32_t flags;           // root descriptors, 1.1 only
    std::vector<DescriptorRange> ranges;  // tables only
    std::uint32_t user_offset;     // first dword in the user-data block
    std::uint32_t user_dwords;     // dwords it occupies
};

struct RootSignatureLayout {
    std::uint32_t version = 0;  // 1 = 1.0, 2 = 1.1, 3 = 1.2
    std::uint32_t flags = 0;
    std::vector<RootParameter> parameters;
    std::vector<std::vector<std::uint32_t>> static_samplers;  // raw D3D12_STATIC_SAMPLER_DESC(1) dwords
    std::uint32_t user_dwords = 0;  // total; above 32 the console spills to memory (layout open)

    bool fits() const { return user_dwords <= user_data_dwords; }
};

// Parses a serialized root signature. False for a malformed blob or an unknown version.
inline bool parse_root_signature(std::span<const std::uint8_t> blob, RootSignatureLayout& out) {
    out = {};
    std::span<const std::uint8_t> rts0 = dxbc_part(blob, "RTS0");
    if (rts0.empty()) rts0 = blob;  // a bare RTS0 part
    const auto u32 = [&](std::size_t at, std::uint32_t& value) {
        if (at + 4 > rts0.size()) return false;
        std::memcpy(&value, rts0.data() + at, 4);
        return true;
    };
    std::uint32_t parameter_count, parameters_at, sampler_count, samplers_at;
    if (!u32(0, out.version) || !u32(4, parameter_count) || !u32(8, parameters_at) || !u32(12, sampler_count) ||
        !u32(16, samplers_at) || !u32(20, out.flags))
        return false;
    if (out.version < 1 || out.version > 3 || parameter_count > 64 || sampler_count > 2048) return false;
    const bool v11 = out.version >= 2;

    for (std::uint32_t i = 0; i < parameter_count; ++i) {
        RootParameter p{};
        std::uint32_t payload;
        const std::size_t at = std::size_t(parameters_at) + 12 * std::size_t(i);
        if (!u32(at, p.type) || !u32(at + 4, p.visibility) || !u32(at + 8, payload)) return false;
        switch (p.type) {
        case root_parameter::constants:
            if (!u32(payload, p.shader_register) || !u32(payload + 4, p.space) || !u32(payload + 8, p.constant_count))
                return false;
            p.user_dwords = p.constant_count;
            break;
        case root_parameter::cbv:
        case root_parameter::srv:
        case root_parameter::uav:
            if (!u32(payload, p.shader_register) || !u32(payload + 4, p.space) || (v11 && !u32(payload + 8, p.flags)))
                return false;
            p.user_dwords = 2;
            break;
        case root_parameter::descriptor_table: {
            std::uint32_t range_count, ranges_at;
            if (!u32(payload, range_count) || !u32(payload + 4, ranges_at) || range_count > 4096) return false;
            const std::size_t stride = v11 ? 24 : 20;
            for (std::uint32_t r = 0; r < range_count; ++r) {
                const std::size_t ra = std::size_t(ranges_at) + stride * r;
                DescriptorRange range{};
                if (!u32(ra, range.type) || !u32(ra + 4, range.count) || !u32(ra + 8, range.base_register) ||
                    !u32(ra + 12, range.space))
                    return false;
                if (v11 ? !(u32(ra + 16, range.flags) && u32(ra + 20, range.table_offset)) : !u32(ra + 16, range.table_offset))
                    return false;
                p.ranges.push_back(range);
            }
            p.user_dwords = 2;
            break;
        }
        default:
            return false;
        }
        p.user_offset = out.user_dwords;
        out.user_dwords += p.user_dwords;
        out.parameters.push_back(std::move(p));
    }

    const std::size_t sampler_dwords = out.version >= 3 ? 14 : 13;
    for (std::uint32_t i = 0; i < sampler_count; ++i) {
        std::vector<std::uint32_t> words(sampler_dwords);
        for (std::size_t w = 0; w < sampler_dwords; ++w)
            if (!u32(std::size_t(samplers_at) + 4 * (sampler_dwords * i + w), words[w])) return false;
        out.static_samplers.push_back(std::move(words));
    }
    return true;
}

} // namespace leonida
