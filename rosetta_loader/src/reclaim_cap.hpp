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
bool install(const Access& acc, uint64_t runtimeBase);
}
