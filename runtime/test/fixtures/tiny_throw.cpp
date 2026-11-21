// Tiny fixture DLL for the loader's x64 unwind test. It is ordinary test code, not game content.
//
// tiny_throw has a normal MSVC frame with .pdata/unwind info, so catching its exception in the EXE requires the
// loader to register the mapped exception directory with RtlAddFunctionTable. tiny_throw_plain never throws and
// gives the no-.pdata test a call that still works when the unwind table is absent.
#include <stdexcept>

extern "C" __declspec(dllexport) int __cdecl tiny_throw(int value) {
    if (value == 0) throw std::runtime_error("leonida tiny_throw");
    return value + 1;
}

extern "C" __declspec(dllexport) int __cdecl tiny_throw_plain(int value) { return value + 1; }
