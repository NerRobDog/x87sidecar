#pragma once
#include <mach/mach.h>
#include <cstddef>
#include <cstdint>
#include <functional>
// F54a bounded reclaim (see reclaim_cap.cpp). Off unless AOE_RECLAIM_BUDGET_US or AOE_RECLAIM_CAP is set.
namespace reclaim_cap {
struct Access {
    std::function<bool(uint64_t, void*, size_t)> read;
    std::function<bool(uint64_t, const void*, size_t)> write;
    std::function<bool(uint64_t, vm_prot_t, size_t)> protect;
};
enum class Result { Off, Refused, Installed, Fatal };   // Fatal: a runtime page could not be made r-x again
struct IcacheRange { uint64_t addr = 0, len = 0; };     // code the tracee must i-cache-invalidate after Installed
// blocked != nullptr: refuse with that reason (logged) when the feature is requested. icache (optional) receives the
// patched range on Installed.
Result install(const Access& acc, uint64_t runtimeBase, const char* blocked = nullptr, IcacheRange* icache = nullptr);
}
