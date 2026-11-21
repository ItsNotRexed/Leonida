// Root-signature parsing against the PC runtime: descriptions are serialized with the host's
// D3D12SerializeVersionedRootSignature (v1.0 and v1.1), parsed by leonida::parse_root_signature, and every field
// is compared with the description. Also checks the user-data layout (section 3.5 of docs/d3d12_vulkan.md), a
// signature larger than the 32 user registers, and that the measured Xbox flag byte survives parsing. Needs only
// d3d12.dll (loaded at run time), no GPU.
#include <windows.h>
#include <d3d12.h>

#include "../src/root_signature.h"

#include <cstdio>
#include <cstring>
#include <vector>

#define CHECK(condition) do {                                    \
    if (!(condition)) {                                          \
        std::fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
        return 1;                                                \
    }                                                            \
} while (0)

namespace {

using SerializeFn = HRESULT(WINAPI*)(const D3D12_VERSIONED_ROOT_SIGNATURE_DESC*, ID3DBlob**, ID3DBlob**);

std::vector<std::uint8_t> serialize(SerializeFn fn, const D3D12_VERSIONED_ROOT_SIGNATURE_DESC& desc) {
    ID3DBlob* blob = nullptr;
    ID3DBlob* error = nullptr;
    std::vector<std::uint8_t> out;
    if (SUCCEEDED(fn(&desc, &blob, &error)) && blob) {
        const auto* p = static_cast<const std::uint8_t*>(blob->GetBufferPointer());
        out.assign(p, p + blob->GetBufferSize());
    } else if (error) {
        std::fprintf(stderr, "serializer: %s\n", static_cast<const char*>(error->GetBufferPointer()));
    }
    if (blob) blob->Release();
    if (error) error->Release();
    return out;
}

}  // namespace

int main() {
    using namespace leonida;
    const HMODULE d3d12 = LoadLibraryExA("d3d12.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const auto fn = d3d12 ? reinterpret_cast<SerializeFn>(
                                reinterpret_cast<void*>(GetProcAddress(d3d12, "D3D12SerializeVersionedRootSignature")))
                          : nullptr;
    if (!fn) {
        std::printf("SKIP: no d3d12.dll serializer on this system\n");
        return 0;
    }

    // v1.0: constants, a root CBV, a two-range table and a static sampler.
    {
        D3D12_DESCRIPTOR_RANGE ranges[2] = {
            {D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 4, 0, 0, 0},
            {D3D12_DESCRIPTOR_RANGE_TYPE_UAV, 1, 0, 2, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND},
        };
        D3D12_ROOT_PARAMETER params[3] = {};
        params[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
        params[0].Constants = {0, 0, 3};
        params[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        params[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
        params[1].Descriptor = {1, 0};
        params[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_VERTEX;
        params[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
        params[2].DescriptorTable = {2, ranges};
        params[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        D3D12_STATIC_SAMPLER_DESC sampler{};
        sampler.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
        sampler.AddressU = sampler.AddressV = sampler.AddressW = D3D12_TEXTURE_ADDRESS_MODE_WRAP;
        sampler.MaxLOD = D3D12_FLOAT32_MAX;
        sampler.ShaderRegister = 3;
        sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        D3D12_VERSIONED_ROOT_SIGNATURE_DESC desc{};
        desc.Version = D3D_ROOT_SIGNATURE_VERSION_1_0;
        desc.Desc_1_0 = {3, params, 1, &sampler, D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT};
        const auto blob = serialize(fn, desc);
        CHECK(!blob.empty());
        RootSignatureLayout layout;
        CHECK(parse_root_signature(blob, layout));
        CHECK(layout.version == 1 && layout.flags == D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT);
        CHECK(layout.parameters.size() == 3 && layout.static_samplers.size() == 1);
        const auto& c = layout.parameters[0];
        CHECK(c.type == root_parameter::constants && c.constant_count == 3 && c.visibility == D3D12_SHADER_VISIBILITY_ALL);
        CHECK(c.user_offset == 0 && c.user_dwords == 3);
        const auto& cbv = layout.parameters[1];
        CHECK(cbv.type == root_parameter::cbv && cbv.shader_register == 1 && cbv.visibility == D3D12_SHADER_VISIBILITY_VERTEX);
        CHECK(cbv.user_offset == 3 && cbv.user_dwords == 2);
        const auto& table = layout.parameters[2];
        CHECK(table.type == root_parameter::descriptor_table && table.ranges.size() == 2 && table.user_offset == 5);
        CHECK(table.ranges[0].type == D3D12_DESCRIPTOR_RANGE_TYPE_SRV && table.ranges[0].count == 4);
        CHECK(table.ranges[1].type == D3D12_DESCRIPTOR_RANGE_TYPE_UAV && table.ranges[1].space == 2 &&
              table.ranges[1].table_offset == D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND);
        CHECK(layout.user_dwords == 7 && layout.fits());
        D3D12_STATIC_SAMPLER_DESC parsed{};
        std::memcpy(&parsed, layout.static_samplers[0].data(), sizeof(parsed));
        CHECK(parsed.Filter == sampler.Filter && parsed.ShaderRegister == 3 && parsed.MaxLOD == D3D12_FLOAT32_MAX &&
              parsed.ShaderVisibility == D3D12_SHADER_VISIBILITY_PIXEL);

        // The Xbox flag byte (0x03000000, measured) is rejected by the PC serializer, so put it into the blob's
        // RTS0 flags field by hand: parsing keeps it and is otherwise unaffected.
        auto xbox = blob;
        const auto rts0 = dxbc_part(xbox, "RTS0");
        CHECK(rts0.size() >= 24);
        const std::size_t flags_at = std::size_t(rts0.data() - xbox.data()) + 20;
        const std::uint32_t flags = layout.flags | 0x03000000u;
        std::memcpy(xbox.data() + flags_at, &flags, 4);
        CHECK(parse_root_signature(xbox, layout) && layout.flags == flags && layout.user_dwords == 7);

        // A bare RTS0 part parses the same.
        const std::vector<std::uint8_t> bare(rts0.begin(), rts0.end());
        CHECK(parse_root_signature(bare, layout) && layout.parameters.size() == 3);
    }

    // v1.1: descriptor and range flags, a pixel-only constant block, a root UAV.
    {
        D3D12_DESCRIPTOR_RANGE1 range{D3D12_DESCRIPTOR_RANGE_TYPE_CBV, 2, 4, 1, D3D12_DESCRIPTOR_RANGE_FLAG_DATA_STATIC, 0};
        D3D12_ROOT_PARAMETER1 params[4] = {};
        params[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
        params[0].DescriptorTable = {1, &range};
        params[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
        params[1].Descriptor = {5, 0, D3D12_ROOT_DESCRIPTOR_FLAG_DATA_VOLATILE};
        params[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
        params[2].Constants = {2, 0, 2};
        params[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        params[3].ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
        params[3].Descriptor = {7, 3, D3D12_ROOT_DESCRIPTOR_FLAG_NONE};
        D3D12_VERSIONED_ROOT_SIGNATURE_DESC desc{};
        desc.Version = D3D_ROOT_SIGNATURE_VERSION_1_1;
        desc.Desc_1_1 = {4, params, 0, nullptr, D3D12_ROOT_SIGNATURE_FLAG_NONE};
        const auto blob = serialize(fn, desc);
        CHECK(!blob.empty());
        RootSignatureLayout layout;
        CHECK(parse_root_signature(blob, layout) && layout.version == 2 && layout.parameters.size() == 4);
        const auto& table = layout.parameters[0];
        CHECK(table.ranges.size() == 1 && table.ranges[0].type == D3D12_DESCRIPTOR_RANGE_TYPE_CBV &&
              table.ranges[0].count == 2 && table.ranges[0].base_register == 4 && table.ranges[0].space == 1 &&
              table.ranges[0].flags == D3D12_DESCRIPTOR_RANGE_FLAG_DATA_STATIC && table.ranges[0].table_offset == 0);
        CHECK(layout.parameters[1].type == root_parameter::uav && layout.parameters[1].shader_register == 5 &&
              layout.parameters[1].flags == D3D12_ROOT_DESCRIPTOR_FLAG_DATA_VOLATILE);
        CHECK(layout.parameters[2].constant_count == 2 && layout.parameters[2].visibility == D3D12_SHADER_VISIBILITY_PIXEL);
        CHECK(layout.parameters[3].type == root_parameter::srv && layout.parameters[3].space == 3);
        // table 0-1, UAV 2-3, constants 4-5, SRV 6-7
        CHECK(layout.parameters[1].user_offset == 2 && layout.parameters[2].user_offset == 4 &&
              layout.parameters[3].user_offset == 6 && layout.user_dwords == 8);
    }

    // More than 32 user dwords: the console spills these (layout open); the parser reports it.
    {
        D3D12_DESCRIPTOR_RANGE range{D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 1, 0, 0, 0};
        std::vector<D3D12_ROOT_PARAMETER> params(20);
        for (UINT i = 0; i < params.size(); ++i) {
            params[i].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
            params[i].DescriptorTable = {1, &range};
        }
        std::vector<D3D12_DESCRIPTOR_RANGE> distinct(20, range);
        for (UINT i = 0; i < params.size(); ++i) {
            distinct[i].BaseShaderRegister = i;
            params[i].DescriptorTable.pDescriptorRanges = &distinct[i];
        }
        D3D12_VERSIONED_ROOT_SIGNATURE_DESC desc{};
        desc.Version = D3D_ROOT_SIGNATURE_VERSION_1_0;
        desc.Desc_1_0 = {UINT(params.size()), params.data(), 0, nullptr, D3D12_ROOT_SIGNATURE_FLAG_NONE};
        const auto blob = serialize(fn, desc);
        RootSignatureLayout layout;
        CHECK(!blob.empty() && parse_root_signature(blob, layout));
        CHECK(layout.user_dwords == 40 && !layout.fits());
    }

    // Malformed input.
    {
        RootSignatureLayout layout;
        const std::vector<std::uint8_t> short_blob(10, 0);
        CHECK(!parse_root_signature(short_blob, layout));
        std::vector<std::uint8_t> bad_version(24, 0);
        bad_version[0] = 9;
        CHECK(!parse_root_signature(bad_version, layout));
    }

    std::printf("root signatures: v1.0 and v1.1 match the PC serializer, user-data layout, Xbox flag byte OK\n");
    return 0;
}
