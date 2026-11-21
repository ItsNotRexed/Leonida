#include "pe_loader.h"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "../shims/shims.h"

namespace rt {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

namespace {

std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + p.string());
    return {std::istreambuf_iterator<char>(f), {}};
}

template <class T>
T* at(uint8_t* base, uint32_t rva) { return reinterpret_cast<T*>(base + rva); }

// Every RVA followed below comes out of the image itself, so each one is checked first. A truncated or corrupt
// image then fails with a message instead of reading, writing or protecting memory outside its allocation.
void require_range(const std::string& name, uint64_t rva, uint64_t len, uint32_t image_size, const char* what) {
    if (rva > image_size || len > image_size - rva)
        throw std::runtime_error(name + ": " + what + " runs past the image");
}

std::string read_string(const std::string& name, uint8_t* base, uint32_t image_size, uint32_t rva, const char* what) {
    if (rva >= image_size) throw std::runtime_error(name + ": " + what + " is outside the image");
    auto* s = reinterpret_cast<const char*>(base + rva);
    auto* end = static_cast<const char*>(std::memchr(s, 0, image_size - rva));
    if (!end) throw std::runtime_error(name + ": " + what + " isn't terminated inside the image");
    return {s, end};
}

// The TLS directory holds virtual addresses, which relocations have already moved to this mapping.
uint64_t rva_in(const Module& m, uint64_t va, const char* what) {
    const uint64_t base = reinterpret_cast<uint64_t>(m.base);
    if (va < base || va - base >= m.size) throw std::runtime_error(m.name + ": " + what + " is outside the image");
    return va - base;
}

IMAGE_TLS_DIRECTORY64* tls_directory(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.Size || !dir.VirtualAddress) return nullptr;
    require_range(m.name, dir.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY64), m.size, "the TLS directory");
    return at<IMAGE_TLS_DIRECTORY64>(m.base, dir.VirtualAddress);
}

// __declspec(thread) reads TEB->ThreadLocalStoragePointer[_tls_index] at gs:[58h]. That array is indexed by the
// loader-assigned per-module TLS index and is a different index space from TlsAlloc/TlsGetValue (TlsSlots). Only the OS
// loader can allocate a module index, so the runtime ships a minimal DLL whose only content is a TLS anchor
// (src/tls_host.cpp). Loading it makes the OS reserve an index and give every thread a block for it; the native loader
// reuses that index for the mapped image. One helper means one mapped TLS module at a time.
constexpr DWORD kMaxModuleTlsSlots = 64;
void** module_tls_slots() { return reinterpret_cast<void**>(__readgsqword(0x58)); }

struct TlsHostModule {
    HMODULE module = nullptr;
    DWORD index = TLS_OUT_OF_INDEXES;
};

TlsHostModule load_tls_host() {
    TlsHostModule host;
    wchar_t exe[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return host;
    const std::filesystem::path path = std::filesystem::path(exe).parent_path() / L"gta6rt_tls_host.dll";
    // The helper is linked with the static CRT (/MT), so it needs only system DLLs. Restricting the dependency search
    // to System32 keeps a game-supplied vcruntime next to the executable from being picked up.
    host.module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!host.module) return host;

    auto* base = reinterpret_cast<uint8_t*>(host.module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = at<IMAGE_NT_HEADERS64>(base, dos->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.Size || !dir.VirtualAddress) {
        FreeLibrary(host.module);
        host.module = nullptr;
        return host;
    }
    auto* tls = at<IMAGE_TLS_DIRECTORY64>(base, dir.VirtualAddress);
    if (!tls->AddressOfIndex) {
        FreeLibrary(host.module);
        host.module = nullptr;
        return host;
    }
    host.index = *reinterpret_cast<DWORD*>(tls->AddressOfIndex);
    return host;
}

TlsHostModule& tls_host() {
    // The helper stays loaded for the process lifetime: unloading it would release the reserved TLS index. Its own
    // per-thread blocks are restored by uninstall_tls_for_thread, so the OS loader can free them normally.
    static TlsHostModule host = load_tls_host();
    return host;
}

std::atomic<Module*> g_tls_slot_owner{nullptr};

// Per-thread installation state. Only one mapped TLS module can own the reserved slot, so one entry per thread is
// enough; the saved pointer is the helper DLL's own block that the OS loader will free at thread exit.
thread_local Module* g_thread_tls_module = nullptr;
thread_local void* g_thread_tls_saved = nullptr;
thread_local void* g_thread_tls_block = nullptr;

// _CxxThrowException fills ExceptionInformation[3] with the throwing module's base by looking the address up in the
// loader's module list. A manually mapped image is not in that list, so vcruntime records 0 and C++ catch handlers
// cannot resolve the throw. This shim supplies the mapped module's base; each module gets its own thunk so no lookup
// is needed.
extern "C" [[noreturn]] void rt_cxx_throw(void* object, void* info, void* image_base) {
    constexpr ULONG_PTR kCxxExceptionMagic = 0x19930520;  // MSVC C++ EH magic (EH_MAGIC_NUMBER3)
    ULONG_PTR params[4] = {kCxxExceptionMagic, reinterpret_cast<ULONG_PTR>(object),
                           reinterpret_cast<ULONG_PTR>(info), reinterpret_cast<ULONG_PTR>(image_base)};
    RaiseException(0xE06D7363, EXCEPTION_NONCONTINUABLE, 4, params);
    std::abort();  // RaiseException with EXCEPTION_NONCONTINUABLE does not return.
}

void* make_cxx_throw_thunk(void* image_base) {
    // mov r8, image_base ; mov rax, rt_cxx_throw ; jmp rax
    uint8_t* const code =
        static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!code) return nullptr;
    uint64_t base = reinterpret_cast<uint64_t>(image_base);
    uint64_t fn = reinterpret_cast<uint64_t>(&rt_cxx_throw);
    uint8_t bytes[32] = {0x49, 0xB8};
    std::memcpy(bytes + 2, &base, 8);
    bytes[10] = 0x48;
    bytes[11] = 0xB8;
    std::memcpy(bytes + 12, &fn, 8);
    bytes[20] = 0xFF;
    bytes[21] = 0xE0;
    std::memset(bytes + 22, 0xCC, sizeof(bytes) - 22);
    std::memcpy(code, bytes, sizeof(bytes));
    DWORD old = 0;
    if (!VirtualProtect(code, sizeof(bytes), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(code, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(bytes));
    return code;
}

// The Xbox builds of the MSVC runtime import the same CRT the desktop does, so the host's own copies are used.
bool prefer_host_copy(const std::string& dll) {
    static const char* names[] = {"vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll",
                                  "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
                                  "concrt140.dll", "vccorlib140.dll", "vcomp140.dll"};
    for (auto* n : names)
        if (dll == n) return true;
    return false;
}

}  // namespace

Loader::~Loader() {
    for (auto* m : order_) {
        // Unwind tables and TLS state must go away before the image and its TLS block are unmapped.
        if (m->function_table) RtlDeleteFunctionTable(static_cast<PRUNTIME_FUNCTION>(m->function_table));
        if (m->tls_index != kNoTlsIndex) {
            // Only the loading thread has this module installed; other threads must uninstall for themselves before
            // the Loader is destroyed.
            uninstall_tls_for_thread(*m);
            Module* owner = m;
            g_tls_slot_owner.compare_exchange_strong(owner, nullptr);
        }
        if (m->tls_block) VirtualFree(m->tls_block, 0, MEM_RELEASE);
        if (m->cxx_throw_thunk) VirtualFree(m->cxx_throw_thunk, 0, MEM_RELEASE);
        if (m->base) VirtualFree(m->base, 0, MEM_RELEASE);
        delete m;
    }
}

Module& Loader::load(const std::filesystem::path& image) {
    std::string key = lower(image.filename().string());
    if (auto it = by_name_.find(key); it != by_name_.end()) return *it->second;
    Module& m = map_image(image);
    bind_imports(m);
    protect_sections(m);
    return m;
}

void Loader::initialise() {
    // order_ is dependency order: a module is pushed after the modules it imports.
    for (auto* m : order_) initialise(*m);
}

void Loader::initialise(Module& m) {
    if (m.initialised) return;

    // TLS was installed by load(); initialise() only delivers the events, so no slot is allocated or written twice.
    run_tls_callbacks(m, DLL_PROCESS_ATTACH);

    // Only a DLL gets DllMain. An EXE's entry point has a different signature and is the caller's to run.
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) && m.entry_rva) {
        if (m.entry_rva >= m.size) throw std::runtime_error(m.name + ": the entry point is outside the image");
        auto entry = reinterpret_cast<BOOL(NTAPI*)(void*, DWORD, void*)>(m.base + m.entry_rva);
        if (!entry(m.base, DLL_PROCESS_ATTACH, nullptr)) {
            m.initialised = true;  // it ran: a second DLL_PROCESS_ATTACH would be wrong
            throw std::runtime_error(m.name + ": DllMain returned FALSE");
        }
    }
    m.initialised = true;
}

Module& Loader::map_image(const std::filesystem::path& path) {
    auto file = read_file(path);
    const std::string name = path.filename().string();
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (file.size() < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error(path.string() + ": not an MZ image");
    if (dos->e_lfanew < 0 || static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size())
        throw std::runtime_error(name + ": the NT headers are outside the file");
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        throw std::runtime_error(name + ": not an x86-64 PE");
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error(name + ": not a PE32+ image");
    auto& oh = nt->OptionalHeader;
    uint64_t sections = static_cast<uint64_t>(dos->e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER) +
                        nt->FileHeader.SizeOfOptionalHeader;
    if (sections + static_cast<uint64_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) > file.size())
        throw std::runtime_error(name + ": the section table runs past the end of the file");
    if (!oh.SizeOfImage || oh.SizeOfHeaders > oh.SizeOfImage || oh.SizeOfHeaders > file.size())
        throw std::runtime_error(name + ": SizeOfHeaders and SizeOfImage don't fit the file");

    auto* m = new Module;
    m->name = name;
    m->path = path;
    m->preferred_base = oh.ImageBase;
    m->size = oh.SizeOfImage;
    m->entry_rva = oh.AddressOfEntryPoint;
    by_name_[lower(m->name)] = m;
    order_.push_back(m);

    m->base = static_cast<uint8_t*>(
        VirtualAlloc(reinterpret_cast<void*>(oh.ImageBase), oh.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!m->base) {
        auto& relocs = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocs.Size)
            throw std::runtime_error(m->name + ": preferred base is taken and the image has no relocations");
        m->base = static_cast<uint8_t*>(VirtualAlloc(nullptr, oh.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m->base) throw std::runtime_error(m->name + ": VirtualAlloc failed");
    }

    std::memcpy(m->base, file.data(), oh.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        uint32_t n = std::min(sec->SizeOfRawData, sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData);
        if (!n) continue;
        if (sec->PointerToRawData > file.size() || n > file.size() - sec->PointerToRawData)
            throw std::runtime_error(m->name + ": section " + std::to_string(i) + " reads past the end of the file");
        require_range(m->name, sec->VirtualAddress, n, m->size, "a section's data");
        std::memcpy(m->base + sec->VirtualAddress, file.data() + sec->PointerToRawData, n);
    }

    int64_t delta = reinterpret_cast<int64_t>(m->base) - static_cast<int64_t>(oh.ImageBase);
    if (delta) {
        m->relocated = true;
        auto& dir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.Size) throw std::runtime_error(m->name + ": the image has no relocations and isn't at its base");
        require_range(m->name, dir.VirtualAddress, dir.Size, m->size, "the relocation table");
        auto* block = at<IMAGE_BASE_RELOCATION>(m->base, dir.VirtualAddress);
        auto* end = reinterpret_cast<uint8_t*>(block) + dir.Size;
        while (reinterpret_cast<uint8_t*>(block) < end) {
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock > end)
                throw std::runtime_error(m->name + ": a relocation block doesn't fit the relocation table");
            auto* entries = reinterpret_cast<uint16_t*>(block + 1);
            size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            for (size_t i = 0; i < count; ++i) {
                uint16_t type = entries[i] >> 12, off = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    require_range(m->name, static_cast<uint64_t>(block->VirtualAddress) + off, sizeof(uint64_t), m->size,
                                  "a relocation");
                    *at<uint64_t>(m->base, block->VirtualAddress + off) += delta;
                } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                    throw std::runtime_error(m->name + ": unsupported relocation type " + std::to_string(type));
                }
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock);
        }
    }
    // The TLS directory and the exception directory hold virtual addresses, so both are read after relocation. TLS is
    // installed here, before bind_imports can return control to the caller and before any image code can run.
    initialize_tls(*m);
    register_unwind(*m);
    parse_exports(*m);
    return *m;
}

// Static TLS for the thread that calls load(). The PE TLS directory only carries the template (Start..End) and the
// zero-fill size; it has no field naming the TLS block. The Windows loader allocates a block per module per thread and
// puts it in TEB->ThreadLocalStoragePointer[module index], which is what __declspec(thread) code reads via _tls_index.
// Only the OS loader can allocate that module index, so the loader reuses the index the OS assigned to
// gta6rt_tls_host.dll. That makes one manually mapped TLS module work; a second one is rejected rather than silently
// sharing (and corrupting) the same slot.
void Loader::initialize_tls(Module& m) {
    auto* tls = tls_directory(m);
    if (!tls) return;
    // A present but all-zero directory is treated like an absent one.
    if (!tls->StartAddressOfRawData && !tls->EndAddressOfRawData && !tls->AddressOfIndex && !tls->AddressOfCallBacks &&
        !tls->SizeOfZeroFill)
        return;
    if (tls->EndAddressOfRawData < tls->StartAddressOfRawData)
        throw std::runtime_error(m.name + ": TLS template end precedes its start");
    uint64_t raw = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
    uint64_t total = raw + tls->SizeOfZeroFill;
    if (total > 0xFFFFFFFFull) throw std::runtime_error(m.name + ": TLS block is too large");
    const uint32_t raw_rva =
        raw ? static_cast<uint32_t>(rva_in(m, tls->StartAddressOfRawData, "the TLS template")) : 0;
    if (raw) require_range(m.name, raw_rva, raw, m.size, "the TLS template");
    uint64_t index_rva = 0;
    if (tls->AddressOfIndex) {
        index_rva = rva_in(m, tls->AddressOfIndex, "the TLS index");
        require_range(m.name, index_rva, sizeof(uint32_t), m.size, "the TLS index");
    }

    DWORD index = tls_host().index;
    if (index == TLS_OUT_OF_INDEXES)
        throw std::runtime_error(m.name + ": gta6rt_tls_host.dll is missing or has no module TLS index");
    if (index >= kMaxModuleTlsSlots) throw std::runtime_error(m.name + ": reserved TLS index is out of range");
    if (!module_tls_slots()) throw std::runtime_error(m.name + ": this thread has no TLS array");

    Module* expected = nullptr;
    if (!g_tls_slot_owner.compare_exchange_strong(expected, &m))
        throw std::runtime_error(m.name + ": only one manually mapped module may use static TLS at a time");

    m.tls_index = index;
    m.tls_template = raw ? m.base + raw_rva : nullptr;
    m.tls_raw_size = static_cast<uint32_t>(raw);
    m.tls_zero_fill = tls->SizeOfZeroFill;
    m.tls_block_size = static_cast<uint32_t>(total);
    // The index lives in a writable section and protect_sections() has not run yet, so the write needs no
    // VirtualProtect dance.
    if (index_rva) *reinterpret_cast<uint32_t*>(m.base + index_rva) = index;
    try {
        install_tls_for_thread(m);
    } catch (...) {
        m.tls_index = kNoTlsIndex;
        g_tls_slot_owner = nullptr;
        throw;
    }
}

void Loader::install_tls_for_thread(Module& m) {
    if (m.tls_index == kNoTlsIndex) return;
    if (g_thread_tls_module == &m) return;
    if (g_thread_tls_module)
        throw std::runtime_error("another manually mapped module's TLS is already installed in this thread");

    const uint64_t total = static_cast<uint64_t>(m.tls_raw_size) + m.tls_zero_fill;
    if (!total) return;
    void** slots = module_tls_slots();
    if (!slots || m.tls_index >= kMaxModuleTlsSlots)
        throw std::runtime_error(m.name + ": cannot install TLS in this thread");

    void* block = VirtualAlloc(nullptr, static_cast<SIZE_T>(total), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!block) throw std::runtime_error(m.name + ": TLS block allocation failed");
    if (m.tls_raw_size) std::memcpy(block, m.tls_template, m.tls_raw_size);
    if (m.tls_zero_fill)
        std::memset(static_cast<uint8_t*>(block) + m.tls_raw_size, 0, m.tls_zero_fill);

    void* saved = slots[m.tls_index];
    slots[m.tls_index] = block;
    g_thread_tls_module = &m;
    g_thread_tls_saved = saved;
    g_thread_tls_block = block;
    if (!m.tls_block) {
        m.tls_block = block;
        m.tls_saved_block = saved;
    }
}

void Loader::uninstall_tls_for_thread(Module& m) {
    if (g_thread_tls_module != &m) return;
    void** slots = module_tls_slots();
    if (slots && m.tls_index < kMaxModuleTlsSlots && slots[m.tls_index] == g_thread_tls_block)
        slots[m.tls_index] = g_thread_tls_saved;
    if (m.tls_block == g_thread_tls_block) {
        m.tls_block = nullptr;
        m.tls_saved_block = nullptr;
    }
    VirtualFree(g_thread_tls_block, 0, MEM_RELEASE);
    g_thread_tls_module = nullptr;
    g_thread_tls_saved = nullptr;
    g_thread_tls_block = nullptr;
}

// x64 only has table-based unwinding. Registers the mapped .pdata so RtlUnwind can walk frames inside this image.
void Loader::register_unwind(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.Size || !dir.VirtualAddress) return;
    require_range(m.name, dir.VirtualAddress, dir.Size, m.size, "the exception directory");
    uint32_t count = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    if (!count) return;
    auto* table = at<IMAGE_RUNTIME_FUNCTION_ENTRY>(m.base, dir.VirtualAddress);
    if (!RtlAddFunctionTable(table, count, reinterpret_cast<DWORD_PTR>(m.base))) {
        // A malformed or unusual .pdata should not stop the image from loading; exceptions through this image will
        // simply have no unwind data.
        std::fprintf(stderr, "[rt] %s: RtlAddFunctionTable failed; unwinding through this image is unavailable\n",
                     m.name.c_str());
        return;
    }
    m.function_table = table;
    m.function_count = count;
}

void Loader::run_tls_callbacks(Module& m, uint32_t reason) {
    auto* tls = tls_directory(m);
    if (!tls || !tls->AddressOfCallBacks) return;
    const uint64_t table_rva = rva_in(m, tls->AddressOfCallBacks, "the TLS callback table");
    // The callback table has no length field: it ends at a zero entry, so every step is checked against the image.
    for (uint64_t i = 0;; ++i) {
        const uint64_t entry_rva = table_rva + i * sizeof(uint64_t);
        require_range(m.name, entry_rva, sizeof(uint64_t), m.size, "a TLS callback table entry");
        const uint64_t fn = *at<uint64_t>(m.base, static_cast<uint32_t>(entry_rva));
        if (!fn) break;
        auto callback =
            reinterpret_cast<PIMAGE_TLS_CALLBACK>(m.base + rva_in(m, fn, "a TLS callback"));
        callback(m.base, static_cast<DWORD>(reason), nullptr);
    }
}

void Loader::parse_exports(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.Size) return;
    require_range(m.name, dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), m.size, "the export directory");
    auto* ed = at<IMAGE_EXPORT_DIRECTORY>(m.base, dir.VirtualAddress);
    require_range(m.name, ed->AddressOfFunctions, static_cast<uint64_t>(ed->NumberOfFunctions) * sizeof(uint32_t), m.size,
                  "the export address table");
    require_range(m.name, ed->AddressOfNames, static_cast<uint64_t>(ed->NumberOfNames) * sizeof(uint32_t), m.size,
                  "the export name table");
    require_range(m.name, ed->AddressOfNameOrdinals, static_cast<uint64_t>(ed->NumberOfNames) * sizeof(uint16_t), m.size,
                  "the export ordinal table");
    auto* funcs = at<uint32_t>(m.base, ed->AddressOfFunctions);
    auto* names = at<uint32_t>(m.base, ed->AddressOfNames);
    auto* ords = at<uint16_t>(m.base, ed->AddressOfNameOrdinals);
    for (uint32_t i = 0; i < ed->NumberOfFunctions; ++i)
        if (funcs[i]) m.exports["#" + std::to_string(ed->Base + i)] = m.base + funcs[i];
    for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
        if (ords[i] >= ed->NumberOfFunctions)
            throw std::runtime_error(m.name + ": an export name points past the address table");
        m.exports[read_string(m.name, m.base, m.size, names[i], "an export name")] = m.base + funcs[ords[i]];
    }
    // Forwarded exports (RVA inside the export directory) aren't followed yet; none of the bundled DLLs use them.
}

void* Loader::resolve(Module& m, const std::string& dll, const std::string& name, uint16_t ordinal, bool by_ordinal) {
    std::string key = lower(dll);
    std::string sym = by_ordinal ? "#" + std::to_string(ordinal) : name;

    // Supplying the mapped module's base makes C++ exceptions from the image resolvable; see rt_cxx_throw.
    if (!by_ordinal && name == "_CxxThrowException" &&
        (key == "vcruntime140.dll" || key == "vcruntime140_1.dll" || key == "msvcp140.dll" ||
         key == "vcruntime140d.dll" || key == "vcruntime140_1d.dll" || key == "msvcp140d.dll")) {
        if (!m.cxx_throw_thunk) m.cxx_throw_thunk = make_cxx_throw_thunk(m.base);
        if (m.cxx_throw_thunk) {
            m.imports.push_back({dll, sym, Binding::Shim});
            return m.cxx_throw_thunk;
        }
    }

    if (void* p = shims::find(key, sym)) {
        m.imports.push_back({dll, sym, Binding::Shim});
        return p;
    }
    // Bundled game module (an Xbox build that ships beside the game)?
    auto bundled = game_dir_ / dll;
    if (!prefer_host_copy(key) && std::filesystem::exists(bundled)) {
        Module& dep = load(bundled);
        if (auto it = dep.exports.find(sym); it != dep.exports.end()) {
            m.imports.push_back({dll, sym, Binding::Module});
            return it->second;
        }
    }
    // Host Windows: system DLLs and API sets. LOAD_LIBRARY_SEARCH_SYSTEM32 keeps the game folder out of the search.
    if (HMODULE h = LoadLibraryExA(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        FARPROC p = GetProcAddress(h, by_ordinal ? MAKEINTRESOURCEA(ordinal) : name.c_str());
        if (p) {
            m.imports.push_back({dll, sym, Binding::Host});
            return reinterpret_cast<void*>(p);
        }
    }
    m.imports.push_back({dll, sym, Binding::Unimplemented});
    return shims::make_unimplemented_thunk(dll, sym);
}

void Loader::bind_imports(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);

    // Thunk tables have no length field: they end at a zero entry, so each step is checked against the image.
    auto bind_thunks = [&](const std::string& dll, uint64_t lookup_rva, uint64_t iat_rva) {
        for (;; lookup_rva += sizeof(IMAGE_THUNK_DATA64), iat_rva += sizeof(IMAGE_THUNK_DATA64)) {
            require_range(m.name, lookup_rva, sizeof(IMAGE_THUNK_DATA64), m.size, "an import lookup table");
            require_range(m.name, iat_rva, sizeof(IMAGE_THUNK_DATA64), m.size, "an import address table");
            auto* lookup = at<IMAGE_THUNK_DATA64>(m.base, static_cast<uint32_t>(lookup_rva));
            if (!lookup->u1.AddressOfData) return;
            bool by_ord = IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal);
            uint16_t ord = by_ord ? (uint16_t)IMAGE_ORDINAL64(lookup->u1.Ordinal) : 0;
            std::string name;
            if (!by_ord) {
                uint32_t hint = static_cast<uint32_t>(lookup->u1.AddressOfData);
                require_range(m.name, hint, sizeof(uint16_t), m.size, "an import name");
                name = read_string(m.name, m.base, m.size, hint + sizeof(uint16_t), "an import name");
            }
            at<IMAGE_THUNK_DATA64>(m.base, static_cast<uint32_t>(iat_rva))->u1.Function =
                reinterpret_cast<uint64_t>(resolve(m, dll, name, ord, by_ord));
        }
    };

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size) {
        for (uint64_t i = 0;; ++i) {
            uint64_t rva = dir.VirtualAddress + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            require_range(m.name, rva, sizeof(IMAGE_IMPORT_DESCRIPTOR), m.size, "the import table");
            auto* d = at<IMAGE_IMPORT_DESCRIPTOR>(m.base, static_cast<uint32_t>(rva));
            if (!d->Name) break;
            std::string dll = read_string(m.name, m.base, m.size, d->Name, "an imported DLL name");
            uint32_t lookup = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
            bind_thunks(dll, lookup, d->FirstThunk);
        }
    }
    // Delay imports are bound eagerly: simpler, and the full import surface shows up in --dry-run.
    auto& ddir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (ddir.Size) {
        for (uint64_t i = 0;; ++i) {
            uint64_t rva = ddir.VirtualAddress + i * sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
            require_range(m.name, rva, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR), m.size, "the delay-import table");
            auto* d = at<IMAGE_DELAYLOAD_DESCRIPTOR>(m.base, static_cast<uint32_t>(rva));
            if (!d->DllNameRVA) break;
            std::string dll = read_string(m.name, m.base, m.size, d->DllNameRVA, "a delay-imported DLL name");
            bind_thunks(dll, d->ImportNameTableRVA, d->ImportAddressTableRVA);
        }
    }
}

void Loader::protect_sections(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    DWORD old;
    VirtualProtect(m.base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        bool x = sec->Characteristics & IMAGE_SCN_MEM_EXECUTE, w = sec->Characteristics & IMAGE_SCN_MEM_WRITE;
        DWORD prot = x ? (w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : (w ? PAGE_READWRITE : PAGE_READONLY);
        uint64_t size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (sec->VirtualAddress >= m.size) continue;
        size = std::min<uint64_t>(size, m.size - sec->VirtualAddress);
        if (size) VirtualProtect(m.base + sec->VirtualAddress, static_cast<SIZE_T>(size), prot, &old);
    }
    FlushInstructionCache(GetCurrentProcess(), m.base, m.size);
}

}  // namespace rt
