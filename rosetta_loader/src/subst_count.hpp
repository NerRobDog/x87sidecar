#pragma once
#include <mach/mach.h>
#include <cstdint>
#include <vector>
// subst_count: proof that the translation-time substitutions (AOE_SUBST_PC/ORIG/NEW, AOE_SUBST_LIST) were APPLIED.
// Only with AOE_SUBST_COUNT=1 (a test/gate switch, never set by the launcher) and a substitution configured, the sidecar allocates one page of counters in the target (its own allocation, never a
// game page); the decoder hook adds 1 to entry i's counter each time it shows entry i's NEW bytes to the decoder.
// The sidecar reads only these counters and writes one status line per entry to AOE_RECLAIM_LOG (else stdout):
//   [subst] watching <n> entries
//   [subst] applied: entry <i> pc 0x<pc> (first after <s> s)
//   [subst] counts at 300 s: <i>:<count> ...
namespace subst_count {
bool allocate(mach_port_t task);              // before the decoder hook is built; no-op without a substitution
uint64_t addr();                               // counter page in the target, 0 = off
void setEntries(const std::vector<uint64_t>& pcs);   // called by the hook builder, entry i -> counter i
void start(mach_port_t task);                  // reader thread
}
