#include "subst_count.hpp"
#include <mach/mach_vm.h>
#include <pthread.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace subst_count {
namespace {
constexpr uint64_t kAddr = 0x7f0070000000ULL;   // fixed, next to the sidecar's other own allocations
constexpr uint64_t kSize = 0x4000;
constexpr size_t kMax = 16;
uint64_t g_addr = 0;
std::vector<uint64_t> g_pcs;
mach_port_t g_task = MACH_PORT_NULL;
FILE* logFile() {
    static FILE* fh = [] {
        const char* p = std::getenv("AOE_RECLAIM_LOG");
        FILE* f = (p && *p) ? fopen(p, "a") : nullptr;
        return f ? f : stdout;
    }();
    return fh;
}
void* reader(void*) {
    FILE* lg = logFile();
    const size_t n = g_pcs.size() < kMax ? g_pcs.size() : kMax;
    fprintf(lg, "[subst] watching %zu entries\n", n); fflush(lg);
    std::vector<bool> seen(n, false);
    bool summary = false;
    const auto t0 = std::chrono::steady_clock::now();
    for (unsigned it = 0;; it++) {
        usleep(it < 40 ? 250000 : 2000000);   // 4 Hz for the first 10 s, then every 2 s
        uint64_t c[kMax] = {0};
        mach_vm_size_t got = 0;
        if (mach_vm_read_overwrite(g_task, g_addr, sizeof c, reinterpret_cast<mach_vm_address_t>(c), &got) != KERN_SUCCESS)
            return nullptr;   // the game has exited
        const long s = long(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t0).count());
        bool all = true;
        for (size_t i = 0; i < n; i++) {
            if (!seen[i] && c[i]) {
                seen[i] = true;
                fprintf(lg, "[subst] applied: entry %zu pc 0x%llx (first after %ld s)\n", i, (unsigned long long)g_pcs[i], s);
                fflush(lg);
            }
            all = all && seen[i];
        }
        if (!summary && s >= 300) {
            summary = true;
            fprintf(lg, "[subst] counts at 300 s:");
            for (size_t i = 0; i < n; i++) fprintf(lg, " %zu:%llu", i, (unsigned long long)c[i]);
            fprintf(lg, "\n"); fflush(lg);
        }
        if (all && summary) return nullptr;
    }
}
}  // namespace

bool allocate(mach_port_t task) {
    const char* l = std::getenv("AOE_SUBST_LIST");
    const char* p = std::getenv("AOE_SUBST_PC");
    if (!((l && *l) || (p && *p))) return false;
    const char* on = std::getenv("AOE_SUBST_COUNT");   // test/gate switch only; players never get the page
    if (!(on && on[0] == '1' && on[1] == '\0')) return false;
    mach_vm_address_t a = kAddr;
    if (mach_vm_allocate(task, &a, kSize, VM_FLAGS_FIXED) != KERN_SUCCESS || a != kAddr) {
        fprintf(logFile(), "[subst] counters not available (allocation failed); substitutions still run\n"); fflush(logFile());
        return false;
    }
    g_addr = kAddr; g_task = task;
    return true;
}
uint64_t addr() { return g_addr; }
void setEntries(const std::vector<uint64_t>& pcs) { g_pcs = pcs; }
void start(mach_port_t task) {
    if (!g_addr || g_pcs.empty()) return;
    g_task = task;
    pthread_t th;
    if (pthread_create(&th, nullptr, reader, nullptr) == 0) pthread_detach(th);
}
}  // namespace subst_count
