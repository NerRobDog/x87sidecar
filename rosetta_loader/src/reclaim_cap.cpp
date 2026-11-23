// reclaim_cap: bounded reclaim of dead translation fragments in Rosetta's runtime (F54a, "Stutter fix").
// AOE_RECLAIM_BUDGET_US=<µs> (and/or AOE_RECLAIM_CAP=<K>) makes every reclaim pass stop after the budget; the next pass continues.
// AOE_RECLAIM_LOG=<file>: one status line ([reclaimcap] installed / not installed: <why>). Off unless a variable is set.
// Fail-closed: the sites are located by structural signatures in the runtime file (reclaim_locate.hpp), the file must be the
// loaded build (LC_UUID), the live code must equal the file, and the three branch words are written all-or-nothing.
// Extracted unchanged (same stubs, same addresses, same log lines) from the sidecar build 827ba3e7.
#include "reclaim_cap.hpp"
#include "reclaim_locate.hpp"

#include <mach-o/loader.h>
#include <mach/mach_vm.h>

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace reclaim_cap {
namespace {

// ── /usr/libexec/rosetta/runtime, macOS 27.2 (26B123) ───────────────────────
// sha256 5d0e8f9a10093a8af1fbae31b59917be2ad1b248c4a71bf570982ba5966c41c4
constexpr uint64_t kOffTextPad = 0x2c400;     // zero padding at the end of __TEXT (r-x)
constexpr uint64_t kOffState = 0x3d000;       // unused tail of __DATA (rw-)

struct Fingerprint {
    uint64_t off;
    uint32_t word;
};
// Build fingerprint of the macOS 27.2 runtime (the words the original patch set was verified against). All match ->
// fast path: the located sites must equal the fixed offsets below. None of these words is written by this file.
constexpr Fingerprint kFingerprint[] = {
    {0x1924, 0xd2800950},   // mov x16, #0x4a
    {0x1928, 0xd4001001},   // svc #0x80
    {0x192c, 0x9a9f37e1},   // cset x1, hs
    {0x1930, 0xd65f03c0},   // ret
    {0x9be0, 0x390683e8},   // strb w8, [sp, #0x1a0]   node.first_page_was_writable (+0xf8)
    {0x9bec, 0x390687e8},   // strb w8, [sp, #0x1a1]   node.last_page_was_writable  (+0xf9)
    {0x9c00, 0x52802302},   // mov w2, #0x118          node size
    {0x9c4c, 0xaa1303e0},   // mov x0, x19
    {0x9c50, 0xaa1503e1},   // mov x1, x21
    {0x9c54, 0x94004290},   // bl unlock
    {0x9c58, 0xaa1603e0},   // mov x0, x22
    {0x13ae8, 0xf940242a},  // ldr x10, [x1, #0x48]    node.x86_begin
    {0x13b18, 0xb9409c29},  // ldr w9, [x1, #0x9c]     node.arm_size (x86_size is the word before)
    {0xb4cc, 0x9274cf60},   // and x0, x27, #~0xfff
    {0xb4d0, 0x52820001},   // mov w1, #0x1000
    {0xb4d4, 0x528000e2},   // mov w2, #7
    {0xb4d8, 0x97ffd913},   // bl mprotect
    {0x1a694, 0xd100c3ff},  // unlock: sub sp, sp, #0x30
};

// ── tiny ARM64 assembler ────────────────────────────────────────────────────
enum : uint32_t { EQ = 0, NE = 1, HS = 2, LO = 3, HI = 8, LS = 9 };
constexpr uint32_t XZR = 31;

struct Asm {
    uint64_t base;
    std::vector<uint32_t> w;
    std::map<std::string, size_t> labels;
    struct Fix {
        size_t pos;
        std::string label;
        int kind;  // 0 b, 1 b.cond, 2 cbz/cbnz
    };
    std::vector<Fix> fixes;
    bool ok = true;

    explicit Asm(uint64_t b) : base(b) {}
    uint64_t here() const { return base + w.size() * 4; }
    void ins(uint32_t v) { w.push_back(v); }
    void label(const char* n) { labels[n] = w.size(); }
    void movAbs(uint32_t rd, uint64_t v) {
        ins(0xD2800000U | ((v & 0xffff) << 5) | rd);
        ins(0xF2A00000U | (((v >> 16) & 0xffff) << 5) | rd);
        ins(0xF2C00000U | (((v >> 32) & 0xffff) << 5) | rd);
        if (v >> 48) ok = false;
    }
    void rel26(uint32_t op, uint64_t target) {
        const int64_t d = static_cast<int64_t>(target) - static_cast<int64_t>(here());
        if (d < -(1LL << 27) || d >= (1LL << 27) || (d & 3)) ok = false;
        ins(op | (static_cast<uint32_t>(d >> 2) & 0x03ffffffU));
    }
    void blTo(uint64_t target) { rel26(0x94000000U, target); }
    void bTo(uint64_t target) { rel26(0x14000000U, target); }
    void b(const char* l) { fixes.push_back({w.size(), l, 0}); ins(0x14000000U); }
    void bcond(uint32_t c, const char* l) { fixes.push_back({w.size(), l, 1}); ins(0x54000000U | c); }
    void cbzW(uint32_t rt, const char* l) { fixes.push_back({w.size(), l, 2}); ins(0x34000000U | rt); }
    void cbnzW(uint32_t rt, const char* l) { fixes.push_back({w.size(), l, 2}); ins(0x35000000U | rt); }
    void ldrW(uint32_t rt, uint32_t rn, uint32_t off) { ins(0xB9400000U | ((off / 4) << 10) | (rn << 5) | rt); }
    void strW(uint32_t rt, uint32_t rn, uint32_t off) { ins(0xB9000000U | ((off / 4) << 10) | (rn << 5) | rt); }
    void ldrX(uint32_t rt, uint32_t rn, uint32_t off) { ins(0xF9400000U | ((off / 8) << 10) | (rn << 5) | rt); }
    void strX(uint32_t rt, uint32_t rn, uint32_t off) { ins(0xF9000000U | ((off / 8) << 10) | (rn << 5) | rt); }
    void ldrB(uint32_t rt, uint32_t rn, uint32_t off) { ins(0x39400000U | (off << 10) | (rn << 5) | rt); }
    void ldrBPost1(uint32_t rt, uint32_t rn) { ins(0x38401400U | (rn << 5) | rt); }
    void addX(uint32_t rd, uint32_t rn, uint32_t rm) { ins(0x8B000000U | (rm << 16) | (rn << 5) | rd); }
    void subX(uint32_t rd, uint32_t rn, uint32_t rm) { ins(0xCB000000U | (rm << 16) | (rn << 5) | rd); }
    void cmpX(uint32_t rn, uint32_t rm) { ins(0xEB00001FU | (rm << 16) | (rn << 5)); }
    void cmpW(uint32_t rn, uint32_t rm) { ins(0x6B00001FU | (rm << 16) | (rn << 5)); }
    void addImm(uint32_t rd, uint32_t rn, uint32_t imm12) { ins(0x91000000U | (imm12 << 10) | (rn << 5) | rd); }
    void addImm4K(uint32_t rd, uint32_t rn) { ins(0x91400400U | (rn << 5) | rd); }  // + 0x1000
    void cselX(uint32_t rd, uint32_t rn, uint32_t rm, uint32_t c) { ins(0x9A800000U | (rm << 16) | (c << 12) | (rn << 5) | rd); }
    void cselW(uint32_t rd, uint32_t rn, uint32_t rm, uint32_t c) { ins(0x1A800000U | (rm << 16) | (c << 12) | (rn << 5) | rd); }
    void movX(uint32_t rd, uint32_t rm) { ins(0xAA0003E0U | (rm << 16) | rd); }
    void movzW(uint32_t rd, uint32_t imm16) { ins(0x52800000U | (imm16 << 5) | rd); }
    void movAbs64(uint32_t rd, uint64_t v) {
        ins(0xD2800000U | ((v & 0xffff) << 5) | rd);
        ins(0xF2A00000U | (((v >> 16) & 0xffff) << 5) | rd);
        ins(0xF2C00000U | (((v >> 32) & 0xffff) << 5) | rd);
        ins(0xF2E00000U | (((v >> 48) & 0xffff) << 5) | rd);
    }
    void eorX(uint32_t rd, uint32_t rn, uint32_t rm) { ins(0xCA000000U | (rm << 16) | (rn << 5) | rd); }
    void mulX(uint32_t rd, uint32_t rn, uint32_t rm) { ins(0x9B007C00U | (rm << 16) | (rn << 5) | rd); }
    void orrWLsl(uint32_t rd, uint32_t rn, uint32_t rm, uint32_t sh) { ins(0x2A000000U | (rm << 16) | (sh << 10) | (rn << 5) | rd); }
    void ubfizX(uint32_t rd, uint32_t rn, uint32_t lsb, uint32_t width) {
        ins(0xD3400000U | (((64 - lsb) & 63) << 16) | ((width - 1) << 10) | (rn << 5) | rd);
    }
    void inc64(uint32_t base_reg, uint32_t off) {  // uses x0
        ldrX(0, base_reg, off);
        addImm(0, 0, 1);
        strX(0, base_reg, off);
    }
    bool finish() {
        for (const auto& f : fixes) {
            auto it = labels.find(f.label);
            if (it == labels.end()) return false;
            const int64_t d = static_cast<int64_t>(it->second) - static_cast<int64_t>(f.pos);
            if (f.kind == 0) {
                w[f.pos] |= static_cast<uint32_t>(d) & 0x03ffffffU;
            } else {
                if (d < -(1 << 18) || d >= (1 << 18)) return false;
                w[f.pos] |= (static_cast<uint32_t>(d) & 0x7ffffU) << 5;
            }
        }
        return ok;
    }
};

bool parseU64(const char* s, uint64_t& out) {
    if (s == nullptr || *s == '\0') return false;
    char* end = nullptr;
    out = std::strtoull(s, &end, 0);
    return end != nullptr && *end == '\0';
}

uint32_t blWord(uint64_t from, uint64_t to) {
    return 0x94000000U | (static_cast<uint32_t>((static_cast<int64_t>(to) - static_cast<int64_t>(from)) >> 2) & 0x03ffffffU);
}

constexpr uint32_t kStRcCount = 0x240;          // u64 fragments freed in the current pass
constexpr uint32_t kStRcCaps = 0x248;           // u64 passes that stopped at the cap (diagnostic)
constexpr uint32_t kStRcRetries = 0x250;        // u64 extra passes from the allocator wrapper (diagnostic)
constexpr uint32_t kStRcGrows = 0x258;          // u64 heap grows through the wrapper (diagnostic)
constexpr uint32_t kStRcT0 = 0x260;             // u64 CNTVCT at the start of the current pass (time budget, F54a-2)
constexpr uint32_t kStRcBudgetHits = 0x268;     // u64 passes that stopped at the time budget (diagnostic)
struct RcState { bool on = false; uint64_t rt = 0, st = 0, K = 0, budgetUs = 0; };
RcState rc;

// ── AOE_RECLAIM_CAP=<K> (F54a, opt-in): bounded freeing of dead JIT fragments.
// Stock reclaim (0x8a4c, run inside a translation with the global translation lock held) frees EVERY dead fragment
// whose epoch is below the minimum in one pass. With this switch a pass frees at most K of them (same list order, same
// epoch rule, nothing else changes) and stops through the runtime's own "keep the rest" exit (0x8bc8). The rest stays
// on the free list for the next pass. To keep memory bounded as in stock, the heap-grow call in the allocator (0x42c0)
// is wrapped: if the retry after a pass still finds no room, the heap lock is dropped, another pass runs and the
// allocation is retried; the heap only grows when a pass frees nothing (the same state in which stock grows).
// Exactness: no fragment is freed earlier than stock would free it (only the timing of freeing moves later); no guest
// instruction, register or memory changes. Exact-bytes gated; off unless the variable is set.
constexpr uint64_t kOffLwPad2 = kOffTextPad + 0x1c00;   // stub area in the text padding (same address as build 827ba3e7)
Result installImpl(const Access& acc, uint64_t rt, const char* blocked, IcacheRange* icache) {
    const char* kv = std::getenv("AOE_RECLAIM_CAP");
    const char* bv = std::getenv("AOE_RECLAIM_BUDGET_US");   // F54a-2: time budget per pass (µs), checked every 64 fragments
    uint64_t K = 0, budgetUs = 0;
    if (kv && (!parseU64(kv, K) || K > 4095)) K = 0;
    if (bv && (!parseU64(bv, budgetUs) || budgetUs > 100000)) budgetUs = 0;
    if (K == 0 && budgetUs == 0) return Result::Off;
    const uint64_t budgetTicks = budgetUs * 24;              // CNTVCT 24 MHz
    FILE* lg = stdout;
    if (const char* rp = std::getenv("AOE_RECLAIM_LOG")) if (*rp) if (FILE* f = fopen(rp, "a")) lg = f;   // install proof for the launcher
    auto refuse = [&](const char* why) { fprintf(lg, "[reclaimcap] not installed: %s\n", why); fflush(lg); return Result::Refused; };
    if (blocked) return refuse(blocked);
    // Sites: exact fingerprint -> the fixed offsets (fast path), and the pattern locator must agree; otherwise the locator
    // alone (reclaim_locate.hpp: structural signatures + cross-checks; any doubt -> refuse = stock behaviour).
    bool fp = true;
    for (const auto& f : kFingerprint) { uint32_t live = 0; if (!acc.read(rt + f.off, &live, 4) || live != f.word) { fp = false; break; } }
    reclaimloc::Sites L; std::string why;
    {
        // Locate on the PRISTINE runtime file (another tool may already have patched the live image), after
        // proving the file is the loaded build (same LC_UUID); then require the live code in every range the locator
        // relies on to equal the file, except branches into the sidecar's own stub padding.
        auto uuidOf = [](const uint8_t* p, size_t n, uint8_t out[16]) {
            if (n < sizeof(mach_header_64)) return false;
            mach_header_64 h; memcpy(&h, p, sizeof h); uint64_t off = sizeof h;
            for (uint32_t i = 0; i < h.ncmds && off + 8 <= n; i++) {
                load_command lc; memcpy(&lc, p + off, sizeof lc);
                if (lc.cmd == LC_UUID && off + sizeof(uuid_command) <= n) { uuid_command u; memcpy(&u, p + off, sizeof u); memcpy(out, u.uuid, 16); return true; }
                off += lc.cmdsize;
            }
            return false;
        };
        std::vector<uint8_t> hdr(0x4000);
        if (!acc.read(rt, hdr.data(), hdr.size())) return refuse("cannot read the runtime header");
        uint8_t uLive[16], uFile[16];
        if (!uuidOf(hdr.data(), hdr.size(), uLive)) return refuse("live runtime has no LC_UUID");
        std::vector<uint8_t> img;
        { FILE* rf = fopen("/usr/libexec/rosetta/runtime", "rb");
          if (!rf) return refuse("cannot open the runtime file");
          fseek(rf, 0, SEEK_END); const long n = ftell(rf); fseek(rf, 0, SEEK_SET);
          if (n <= 0 || n > 0x800000) { fclose(rf); return refuse("runtime file size unexpected"); }
          img.resize(size_t(n)); const size_t got = fread(img.data(), 1, img.size(), rf); fclose(rf);
          if (got != img.size()) return refuse("cannot read the runtime file"); }
        uint32_t magic = 0; memcpy(&magic, img.data(), 4);
        if (magic != MH_MAGIC_64) return refuse("runtime file is not a thin arm64 Mach-O");
        if (!uuidOf(img.data(), img.size(), uFile) || memcmp(uLive, uFile, 16)) return refuse("runtime file is not the loaded build (UUID)");
        reclaimloc::Image im; im.p = img.data(); im.size = img.size();
        // TEST ONLY (fail-closed gate, never set in shipping configs): AOE_RECLAIM_TEST_MUTATE=1 corrupts the locator's LOCAL
        // copy (every casa in the image -> nop) and takes the "build differs" path -> must refuse = stock reclaim;
        // =2 takes the "build differs" path on the intact copy -> exercises the LOCATED install end to end.
        if (const char* tm = std::getenv("AOE_RECLAIM_TEST_MUTATE")) {
            fp = false;
            if (tm[0] == '1') for (size_t o = 0; o + 4 <= img.size(); o += 4) {
                uint32_t w; memcpy(&w, &img[o], 4);
                if ((w & 0xFFE0FC00U) == 0x88E07C00U) { w = 0xD503201FU; memcpy(&img[o], &w, 4); }
            }
            fprintf(lg, "[reclaimcap] TEST: mutate=%c (local copy only)\n", tm[0]);
        }
        // parseImage needs __DATA within the view: extend with zero-fill (bss) to the segment end
        { reclaimloc::Image tmp = im; tmp.size = UINT64_MAX; std::string w2; uint64_t dHi = 0;
          mach_header_64 h; memcpy(&h, img.data(), sizeof h); uint64_t off = sizeof h;
          for (uint32_t i = 0; i < h.ncmds; i++) { load_command lc; memcpy(&lc, &img[off], sizeof lc);
              if (lc.cmd == LC_SEGMENT_64) { segment_command_64 sg; memcpy(&sg, &img[off], sizeof sg);
                  if (!strncmp(sg.segname, "__DATA", 16)) dHi = sg.vmaddr + sg.vmsize; }
              off += lc.cmdsize; }
          (void)tmp; (void)w2;
          if (dHi > img.size() && dHi < 0x800000) img.resize(dHi, 0);
          im.p = img.data(); im.size = img.size(); }
        if (!reclaimloc::parseImage(im, why) || !reclaimloc::locate(im, L, why)) {
            fprintf(lg, "[reclaimcap] locator: %s\n", why.c_str());
            return refuse(fp ? "fingerprint matches but the locator refused" : "runtime build differs and the locator refused");
        }
        // live == file in every range the stubs and the checks depend on; branches into the padding are allowed
        struct Rg { uint64_t lo, hi; } rgs[] = {{L.reclaimFn, L.exitKeep + 8}, {L.growCall - 40, L.allocResume + 8},
                                                {L.lockFn, L.lockFn + 40}, {L.unlockFn, L.unlockFn + 40}, {L.minEpochFn, L.minEpochFn + 64}};
        for (const auto& r : rgs) {
            std::vector<uint8_t> live(r.hi - r.lo);
            if (!acc.read(rt + r.lo, live.data(), live.size())) return refuse("cannot read live code");
            for (uint64_t o = 0; o + 4 <= live.size(); o += 4) {
                uint32_t lw2, fw; memcpy(&lw2, &live[o], 4); memcpy(&fw, &img[r.lo + o], 4);
                if (lw2 == fw) continue;
                const uint64_t at = rt + r.lo + o;
                const bool br = (lw2 & 0x7C000000U) == 0x14000000U;   // b / bl
                const uint64_t tgt = at + uint64_t(reclaimloc::sext(lw2 & 0x03FFFFFFU, 26) * 4);
                if (!br || tgt < rt + L.padLo || tgt >= rt + L.padHi) return refuse("live code differs from the runtime file");
                const uint64_t a = r.lo + o;
                if (a == L.resetCall || a == L.backEdge || a == L.growCall) return refuse("a patch site is already patched");
            }
        }
    }
    if (fp) {   // fast path: the located sites must be exactly the verified fixed offsets
        const bool same = L.reclaimFn == 0x8a4c && L.resetCall == 0x8a70 && L.minEpochFn == 0x55d4 && L.loopHead == 0x8ab4 &&
                          L.backEdge == 0x8bb0 && L.exitKeep == 0x8bc8 && L.growCall == 0x42c0 && L.growFn == 0x4378 &&
                          L.bestFitFn == 0x431c && L.allocResume == 0x42cc && L.lockFn == 0x1a5d0 && L.unlockFn == 0x1a694 &&
                          L.heapLock == 0x3b568 && L.freeListHead == 0x3ba58 && L.padLo == kOffTextPad && L.stateLo == kOffState &&
                          L.wReset == 0x97fff2d9U && L.wBackEdge == 0x17ffffc1U && L.wGrow == 0x9400002eU;
        if (!same) return refuse("fingerprint matches but the located sites differ");
    }
    fprintf(lg, "[reclaimcap] sites %s: reclaim 0x%llx reset 0x%llx back-edge 0x%llx exit 0x%llx grow 0x%llx\n", fp ? "fixed (fingerprint, locator agrees)" : "LOCATED (runtime build differs)",
            (unsigned long long)L.reclaimFn, (unsigned long long)L.resetCall, (unsigned long long)L.backEdge, (unsigned long long)L.exitKeep, (unsigned long long)L.growCall);
    const uint64_t st = rt + L.stateLo;
    const uint64_t padAt = L.padLo + (kOffLwPad2 - kOffTextPad);
    Asm s(rt + padAt);
    // (1) per-pass counter reset on the pass's own call to compute the minimum epoch (0x8a70: bl 0x55d4)
    const uint64_t resetStub = s.here();
    s.movAbs(17, st);
    s.ins(0xF900001FU | ((kStRcCount / 8) << 10) | (17U << 5));   // str xzr, [x17, #count]
    s.ins(0xD53BE050U);                                            // mrs x16, cntvct_el0
    s.strX(16, 17, kStRcT0);                                       // pass start
    s.bTo(rt + L.minEpochFn);                                            // tail call, lr = 0x8a74
    // (2) loop back-edge 0x8bb0 (b 0x8ab4: next fragment x21 = x28 is eligible): count, stop at K
    const uint64_t capStub = s.here();
    s.movAbs(17, st);
    s.ldrX(16, 17, kStRcCount);
    s.addImm(16, 16, 1);
    s.strX(16, 17, kStRcCount);
    if (K) {
        s.ins(0xF100001FU | (static_cast<uint32_t>(K & 0xfff) << 10) | (16U << 5));   // cmp x16, #K (K <= 4095)
        s.bcond(HS, "cap");
    }
    if (budgetTicks) {
        s.ins(0xF240161FU);                                        // tst x16, #63: check the clock every 64 fragments
        s.bcond(NE, "cont");
        s.ins(0xD53BE050U);                                        // mrs x16, cntvct_el0
        s.ldrX(17, 17, kStRcT0);
        s.subX(16, 16, 17);
        s.ins(0xD2800000U | (static_cast<uint32_t>(budgetTicks & 0xffff) << 5) | 17U);          // movz x17, #lo16
        s.ins(0xF2A00000U | (static_cast<uint32_t>((budgetTicks >> 16) & 0xffff) << 5) | 17U);  // movk x17, #hi16, lsl 16
        s.cmpX(16, 17);
        s.bcond(HS, "budget");
    }
    s.label("cont");
    s.bTo(rt + L.loopHead);                                            // continue the loop as stock
    s.label("budget");
    s.movAbs(17, st);
    s.ldrX(16, 17, kStRcBudgetHits);
    s.addImm(16, 16, 1);
    s.strX(16, 17, kStRcBudgetHits);
    s.bTo(rt + L.exitKeep);
    s.label("cap");
    s.ldrX(16, 17, kStRcCaps);
    s.addImm(16, 16, 1);
    s.strX(16, 17, kStRcCaps);
    s.bTo(rt + L.exitKeep);                                            // stock exit: free-list head = x28 (the rest), unlock
    // (3) allocator grow call 0x42c0 (heap lock 0x3b568 held, x19 = thread arg, w20 = size + 7)
    const uint64_t growStub = s.here();
    s.ins(0xA9BE7BFDU);                 // stp x29, x30, [sp, #-32]!
    s.ins(0x910003FDU);                 // mov x29, sp
    s.ins(0xA90157F4U);                 // stp x20, x21, [sp, #16]  (x21 used as scratch, restored)
    s.label("again");
    s.movAbs(16, rt + L.freeListHead);
    s.ldrX(21, 16, 0);                  // free-list head before the pass
    s.ins(0xB4000000U | 21U);           // cbz x21 -> grow (patched below)
    const size_t cbzPos = s.w.size() - 1;
    s.movAbs(0, rt + L.heapLock);          // unlock the heap lock
    s.movX(1, 19);
    s.blTo(rt + L.unlockFn);
    s.movX(0, 19);                      // another reclaim pass
    s.blTo(rt + L.reclaimFn);
    s.movAbs(0, rt + L.heapLock);          // re-lock
    s.movX(1, 19);
    s.blTo(rt + L.lockFn);
    s.movAbs(17, st);
    s.ldrX(16, 17, kStRcRetries);
    s.addImm(16, 16, 1);
    s.strX(16, 17, kStRcRetries);
    s.ins(0x121D7280U | (20U << 5));    // and w0, w20, #0xfffffff8
    s.blTo(rt + L.bestFitFn);                // retry the best-fit allocation
    s.ins(0xB5000000U | 0U);            // cbnz x0 -> got (patched below)
    const size_t cbnzPos = s.w.size() - 1;
    s.movAbs(16, rt + L.freeListHead);         // progress? (head changed) -> try again, else grow
    s.ldrX(16, 16, 0);
    s.cmpX(16, 21);
    s.bcond(NE, "again");
    s.label("grow");
    s.movAbs(17, st);
    s.ldrX(16, 17, kStRcGrows);
    s.addImm(16, 16, 1);
    s.strX(16, 17, kStRcGrows);
    s.ins(0xA94157F4U);                 // ldp x20, x21, [sp, #16]
    s.ins(0xA8C27BFDU);                 // ldp x29, x30, [sp], #32
    s.movX(0, 19);
    s.bTo(rt + L.growFn);                 // the displaced call, as a tail call (returns to 0x42c4 as stock)
    s.label("got");
    s.ins(0xA94157F4U);                 // ldp x20, x21, [sp, #16]
    s.ins(0xA8C27BFDU);                 // ldp x29, x30, [sp], #32
    s.movAbs(30, rt + L.allocResume);          // resume after the allocate_from_node call: 0x42cc mov x21, x0
    s.ins(0xD65F03C0U);                 // ret
    if (!s.finish()) return refuse("stub assembly failed");
    // patch the two forward conditional branches (cbz/cbnz imm19)
    auto setImm19 = [&](size_t pos, const char* label) {
        const int64_t d = static_cast<int64_t>(s.labels[label]) - static_cast<int64_t>(pos);
        s.w[pos] |= (static_cast<uint32_t>(d) & 0x7ffffU) << 5;
    };
    setImm19(cbzPos, "grow");
    setImm19(cbnzPos, "got");
    if (padAt + s.w.size() * 4 > L.padHi) return refuse("stub too large");
    std::vector<uint8_t> probe(s.w.size() * 4);
    if (!acc.read(rt + padAt, probe.data(), probe.size())) return refuse("cannot read the text padding");
    for (uint8_t b : probe) if (b != 0) return refuse("text padding is in use");
    // The stubs store to the __DATA tail: it must be live and writable, or nothing is patched (the zero tail in the
    // file says nothing about the live mapping).
    const uint64_t z[6] = {0, 0, 0, 0, 0, 0};
    if (!acc.write(st + kStRcCount, z, 48)) return refuse("cannot write the state in the __DATA tail (nothing patched)");
    { uint64_t back[6] = {1, 1, 1, 1, 1, 1};
      if (!acc.read(st + kStRcCount, back, 48) || memcmp(back, z, 48)) return refuse("state in the __DATA tail does not read back (nothing patched)"); }
    // Stubs into the zero padding. Its page may also hold live code (on another build), so it must be r-x again
    // afterwards: one retry, else Fatal (the caller must not resume the process with that page non-executable).
    if (!acc.protect(rt + padAt, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, s.w.size() * 4)) return refuse("cannot make the text padding writable");
    const bool stubsWritten = acc.write(rt + padAt, s.w.data(), s.w.size() * 4);
    if (!acc.protect(rt + padAt, VM_PROT_READ | VM_PROT_EXECUTE, s.w.size() * 4) &&
        !acc.protect(rt + padAt, VM_PROT_READ | VM_PROT_EXECUTE, s.w.size() * 4)) {
        fprintf(lg, "[reclaimcap] FATAL: cannot restore r-x on the text padding\n"); fflush(lg);
        return Result::Fatal;
    }
    if (!stubsWritten) return refuse("cannot write the stubs");
    const uint32_t blReset = blWord(rt + L.resetCall, resetStub);
    const uint32_t bCap = 0x14000000U | (static_cast<uint32_t>((static_cast<int64_t>(capStub) - static_cast<int64_t>(rt + L.backEdge)) >> 2) & 0x03ffffffU);
    const uint32_t blGrow = blWord(rt + L.growCall, growStub);
    // all-or-nothing: make every site writable first; only if all succeed, write the three words in a safe order
    // (grow wrapper first: alone it only adds exact retry passes; then the per-pass reset; the cap/budget exit last).
    // If any write fails, the words already written are restored to their gated originals.
    struct Site { uint64_t off; uint32_t word, orig; } sites[] = {{L.growCall, blGrow, L.wGrow}, {L.resetCall, blReset, L.wReset},
                                                                  {L.backEdge, bCap, L.wBackEdge}};
    int prot = 0;
    for (; prot < 3; prot++)
        if (!acc.protect(rt + sites[prot].off, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, 4)) break;
    if (prot < 3) {
        bool rxBack = true;
        for (int i = 0; i < prot; i++) rxBack &= acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_EXECUTE, 4) ||
                                                   acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_EXECUTE, 4);
        if (!rxBack) { fprintf(lg, "[reclaimcap] FATAL: cannot restore r-x on a runtime page\n"); fflush(lg); return Result::Fatal; }
        return refuse("cannot make a site writable (nothing patched)");
    }
    int wrote = 0;
    for (; wrote < 3; wrote++)
        if (!acc.write(rt + sites[wrote].off, &sites[wrote].word, 4)) break;
    bool rolledBack = true;
    if (wrote < 3)
        for (int i = wrote - 1; i >= 0; i--) rolledBack &= acc.write(rt + sites[i].off, &sites[i].orig, 4);
    // Every site page must be executable again before the tracee runs. One retry per site; if a page stays
    // non-executable the process cannot continue safely, so the caller is told (Result::Fatal) instead of "installed".
    bool rx = true;
    for (int i = 0; i < 3; i++)
        if (!acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_EXECUTE, 4) &&
            !acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_EXECUTE, 4)) rx = false;
    if (!rx) {
        // Roll back to stock (writable again, original words), then try r-x once more on every site. Only if a page
        // still can't be made executable is it Fatal.
        for (int i = 2; i >= 0; i--)
            if (acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, 4)) acc.write(rt + sites[i].off, &sites[i].orig, 4);
        bool rxAgain = true;
        for (int i = 0; i < 3; i++) rxAgain &= acc.protect(rt + sites[i].off, VM_PROT_READ | VM_PROT_EXECUTE, 4);
        if (rxAgain) return refuse("cannot restore r-x on a site (rolled back to stock)");
        fprintf(lg, "[reclaimcap] FATAL: cannot restore r-x on a patched runtime page\n"); fflush(lg);
        return Result::Fatal;
    }
    if (wrote < 3) return refuse(rolledBack ? "cannot write a site (rolled back to stock)" : "cannot write a site and the rollback failed");
    if (icache) {   // what the tracee must i-cache-invalidate (cooperative mode): the three sites and the stubs
        uint64_t lo = std::min({L.growCall, L.resetCall, L.backEdge, padAt}), hi = std::max({L.growCall, L.resetCall, L.backEdge}) + 4;
        hi = std::max(hi, padAt + s.w.size() * 4);
        icache->addr = rt + lo; icache->len = hi - lo;
    }
    rc.on = true; rc.rt = rt; rc.st = rt + L.stateLo; rc.K = K; rc.budgetUs = budgetUs;
    fprintf(lg, "[reclaimcap] installed: K=%llu budget_us=%llu, stubs 0x%llx (%zu bytes)\n", (unsigned long long)K, (unsigned long long)budgetUs,
            (unsigned long long)(rt + kOffLwPad2), s.w.size() * 4);
    fflush(lg);
    return Result::Installed;
}

}  // namespace

Result install(const Access& acc, uint64_t rt, const char* blocked, IcacheRange* icache) { return installImpl(acc, rt, blocked, icache); }

}  // namespace reclaim_cap
