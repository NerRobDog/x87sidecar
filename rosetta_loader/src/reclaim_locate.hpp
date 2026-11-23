// reclaim_locate.hpp — find F54a's patch sites in Rosetta's runtime by structure, not by fixed offsets (2026-11-22).
// Pure function over an image view (bytes indexed by VM offset, vmaddr 0 as in /usr/libexec/rosetta/runtime), so the same
// code runs in the sidecar (live image read through the task port) and in the offline test tool (file + mutated copies).
// Every check must pass; any doubt -> no result (the caller then refuses = stock behaviour).
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <mach-o/loader.h>

namespace reclaimloc {

struct Sites {
    uint64_t reclaimFn = 0;      // reclaim pass entry (stock 0x8a4c)
    uint64_t resetCall = 0;      // bl minEpoch inside the pass (0x8a70)
    uint64_t minEpochFn = 0;     // (0x55d4)
    uint64_t loopHead = 0;       // (0x8ab4)
    uint64_t backEdge = 0;       // b loopHead (0x8bb0)
    uint64_t exitKeep = 0;       // keep-the-rest exit (0x8bc8)
    uint64_t growCall = 0;       // bl grow in the allocator (0x42c0)
    uint64_t growFn = 0;         // (0x4378)
    uint64_t bestFitFn = 0;      // (0x431c)
    uint64_t allocResume = 0;    // mov Xr, x0 after alloc_from_node (0x42cc)
    uint64_t lockFn = 0, unlockFn = 0;          // (0x1a5d0, 0x1a694)
    uint64_t heapLock = 0, freeListHead = 0;    // __DATA globals (0x3b568, 0x3ba58)
    uint64_t padLo = 0, padHi = 0;              // zero padding at the end of __TEXT
    uint64_t stateLo = 0, stateHi = 0;          // zero tail of __DATA (zero-fill)
    // original words at the three patch sites (for the write-time re-check)
    uint32_t wReset = 0, wBackEdge = 0, wGrow = 0;
};

struct Image {
    const uint8_t* p = nullptr; uint64_t size = 0;      // p[off] = byte at VM offset off (file view: zero-fill beyond)
    uint64_t textLo = 0, textHi = 0;                    // __TEXT,__text
    uint64_t textSegEnd = 0, lastTextSect = 0;          // __TEXT vmsize, end of the last __TEXT section
    uint64_t dataLo = 0, dataHi = 0, lastDataSect = 0;  // __DATA segment and end of its last section
};

// Parse the Mach-O header at p[0] (thin arm64, vmaddr 0). Returns false if the layout is not the expected shape.
inline bool parseImage(Image& im, std::string& why) {
    if (im.size < sizeof(mach_header_64)) { why = "image too small"; return false; }
    mach_header_64 h; memcpy(&h, im.p, sizeof h);
    if (h.magic != MH_MAGIC_64 || h.cputype != CPU_TYPE_ARM64) { why = "not a thin arm64 Mach-O"; return false; }
    uint64_t off = sizeof h;
    for (uint32_t i = 0; i < h.ncmds; i++) {
        load_command lc; if (off + sizeof lc > im.size) { why = "load commands truncated"; return false; }
        memcpy(&lc, im.p + off, sizeof lc);
        if (lc.cmd == LC_SEGMENT_64) {
            segment_command_64 sg; memcpy(&sg, im.p + off, sizeof sg);
            const bool text = !strncmp(sg.segname, "__TEXT", 16), data = !strncmp(sg.segname, "__DATA", 16);
            if (text) { if (sg.vmaddr != 0) { why = "__TEXT not at vmaddr 0"; return false; } im.textSegEnd = sg.vmsize; }
            if (data) { im.dataLo = sg.vmaddr; im.dataHi = sg.vmaddr + sg.vmsize; }
            for (uint32_t k = 0; k < sg.nsects; k++) {
                section_64 s; memcpy(&s, im.p + off + sizeof sg + k * sizeof s, sizeof s);
                if (text) {
                    im.lastTextSect = std::max<uint64_t>(im.lastTextSect, s.addr + s.size);
                    if (!strncmp(s.sectname, "__text", 16)) { im.textLo = s.addr; im.textHi = s.addr + s.size; }
                }
                if (data) im.lastDataSect = std::max<uint64_t>(im.lastDataSect, s.addr + s.size);
            }
        }
        off += lc.cmdsize;
    }
    if (!im.textHi || !im.textSegEnd || !im.dataHi) { why = "segments/sections not found"; return false; }
    if (im.dataHi > im.size) { why = "image view shorter than __DATA"; return false; }
    return true;
}

// ── A64 decoding helpers (only what the signatures need) ──
inline int64_t sext(uint64_t v, int bits) { const uint64_t m = 1ULL << (bits - 1); return int64_t((v ^ m) - m); }
struct Dec {
    const Image& im;
    uint32_t w(uint64_t a) const { uint32_t x = 0; if (a + 4 <= im.size) memcpy(&x, im.p + a, 4); return x; }
    static bool isB(uint32_t x) { return (x & 0xFC000000U) == 0x14000000U; }
    static bool isBL(uint32_t x) { return (x & 0xFC000000U) == 0x94000000U; }
    static uint64_t brTarget(uint64_t a, uint32_t x) { return a + sext(x & 0x03FFFFFFU, 26) * 4; }
    static bool isBcond(uint32_t x, uint32_t c) { return (x & 0xFF000010U) == 0x54000000U && (x & 0xF) == c; }
    static uint64_t imm19Target(uint64_t a, uint32_t x) { return a + sext((x >> 5) & 0x7FFFF, 19) * 4; }
    static bool isCBZx(uint32_t x) { return (x & 0xFF000000U) == 0xB4000000U; }
    static bool isCBNZx(uint32_t x) { return (x & 0xFF000000U) == 0xB5000000U; }
    static uint32_t rd(uint32_t x) { return x & 31; }
    static uint32_t rn(uint32_t x) { return (x >> 5) & 31; }
    static uint32_t rm(uint32_t x) { return (x >> 16) & 31; }
    static bool isLdrX(uint32_t x) { return (x & 0xFFC00000U) == 0xF9400000U; }
    static bool isStrX(uint32_t x) { return (x & 0xFFC00000U) == 0xF9000000U; }
    static uint64_t ldstOffX(uint32_t x) { return ((x >> 10) & 0xFFF) * 8; }
    static bool isLdrb(uint32_t x) { return (x & 0xFFC00000U) == 0x39400000U; }
    static bool isMovX(uint32_t x) { return (x & 0xFFE0FFE0U) == 0xAA0003E0U; }     // orr xd, xzr, xm
    static bool isCmpX(uint32_t x) { return (x & 0xFFE0FC1FU) == 0xEB00001FU; }     // subs xzr, xn, xm
    static bool isCmpWimm(uint32_t x, uint32_t imm) { return (x & 0xFFC0001FU) == 0x7100001FU && ((x >> 10) & 0xFFF) == imm; }
    static bool isAdrp(uint32_t x) { return (x & 0x9F000000U) == 0x90000000U; }
    static uint64_t adrpTarget(uint64_t a, uint32_t x) {
        const uint64_t imm = (((x >> 5) & 0x7FFFF) << 2) | ((x >> 29) & 3);
        return (a & ~0xFFFULL) + uint64_t(sext(imm, 21) << 12);
    }
    static bool isAddXimm(uint32_t x) { return (x & 0xFFC00000U) == 0x91000000U; }  // add xd, xn, #imm (no shift)
    static uint64_t addImm(uint32_t x) { return (x >> 10) & 0xFFF; }
    static bool isSubSpImm(uint32_t x) { return (x & 0xFFC003FFU) == 0xD10003FFU; }
    static bool isStpPre(uint32_t x) { return (x & 0xFFC003E0U) == 0xA98003E0U; }   // stp x?, x?, [sp, #-n]!
    static bool isRet(uint32_t x) { return x == 0xD65F03C0U; }
    static bool isAddW7(uint32_t x, uint32_t r) { return x == (0x11001C00U | (r << 5) | r); }               // add wR, wR, #7
    static bool isAndNot7(uint32_t x, uint32_t d, uint32_t n) { return x == (0x121D7000U | (n << 5) | d); }  // and wD, wN, #~7
    static bool isCasaW(uint32_t x) { return (x & 0xFFE0FC00U) == 0x88E07C00U; }
    static bool isSwplWzr(uint32_t x) { return (x & 0xFFFFFC00U) == 0xB87F8000U; }
    static bool isMovz128M(uint32_t x) { return (x & 0xFFFFFFE0U) == 0xD2A10000U || (x & 0xFFFFFFE0U) == 0x52A10000U; }
    // resolve "adrp xR, page; add xR, xR, #lo" ending at a (the add) -> address, or 0
    uint64_t adrpAdd(uint64_t addAt, uint32_t r) const {
        const uint32_t ad = w(addAt), ap = w(addAt - 4);
        if (!isAddXimm(ad) || rd(ad) != r || rn(ad) != r || !isAdrp(ap) || rd(ap) != r) return 0;
        return adrpTarget(addAt - 4, ap) + addImm(ad);
    }
};

inline bool allZero(const Image& im, uint64_t lo, uint64_t hi) {
    for (uint64_t a = lo; a < hi; a++) if (im.p[a]) return false;
    return true;
}

// The locator. On success fills s and returns true; otherwise why says which check failed.
inline bool locate(const Image& im, Sites& s, std::string& why) {
    Dec d{im};
    auto fail = [&](const char* m) { why = m; return false; };
    // 1) the reclaim loop's eligibility block: cbz Xa; ldr Xb,[Xa,#0x100]; mov Xc,Xa; cmp Xb,Xd; b.hs EXIT; b HEAD
    std::vector<uint64_t> hits;
    for (uint64_t a = im.textLo; a + 24 <= im.textHi; a += 4) {
        const uint32_t i0 = d.w(a);
        if (!Dec::isCBZx(i0)) continue;
        const uint32_t xa = Dec::rd(i0), i1 = d.w(a + 4), i2 = d.w(a + 8), i3 = d.w(a + 12), i4 = d.w(a + 16), i5 = d.w(a + 20);
        if (!Dec::isLdrX(i1) || Dec::rn(i1) != xa || Dec::ldstOffX(i1) != 0x100) continue;
        if (!Dec::isMovX(i2) || Dec::rm(i2) != xa) continue;
        if (!Dec::isCmpX(i3) || Dec::rn(i3) != Dec::rd(i1)) continue;
        if (!Dec::isBcond(i4, 2 /*HS*/) || !Dec::isB(i5)) continue;
        hits.push_back(a);
    }
    if (hits.size() != 1) return fail(hits.empty() ? "eligibility block not found" : "eligibility block not unique");
    const uint64_t E = hits[0];
    const uint32_t xa = Dec::rd(d.w(E)), xc = Dec::rd(d.w(E + 8));
    s.backEdge = E + 20; s.wBackEdge = d.w(s.backEdge);
    s.loopHead = Dec::brTarget(s.backEdge, s.wBackEdge);
    s.exitKeep = Dec::imm19Target(E + 16, d.w(E + 16));
    if (s.loopHead >= E || s.loopHead < im.textLo || s.exitKeep <= E + 20 || s.exitKeep >= im.textHi) return fail("loop targets out of shape");
    // 2) loop head reads the fragment kind: ldrb wK,[Xc,#0x40]; cmp wK,#4
    { const uint32_t h0 = d.w(s.loopHead), h1 = d.w(s.loopHead + 4);
      if (!Dec::isLdrb(h0) || Dec::rn(h0) != xc || ((h0 >> 10) & 0xFFF) != 0x40 || !Dec::isCmpWimm(h1, 4) || Dec::rn(h1) != Dec::rd(h0))
          return fail("loop head is not the fragment-kind test"); }
    // 3) keep-the-rest exit stores the not-yet-freed fragment Xa as the new free-list head G (a __DATA global)
    { const uint32_t e0 = d.w(s.exitKeep), e1 = d.w(s.exitKeep + 4);
      if (!Dec::isAdrp(e0) || !Dec::isStrX(e1) || Dec::rn(e1) != Dec::rd(e0) || Dec::rd(e1) != xa) return fail("exit does not keep the rest");
      s.freeListHead = Dec::adrpTarget(s.exitKeep, e0) + Dec::ldstOffX(e1); }
    if (s.freeListHead < im.dataLo || s.freeListHead >= im.dataHi) return fail("free-list head not in __DATA");
    // 4) reclaim function entry: nearest "sub sp, sp, #imm" above the loop head, preceded by the end of another function
    for (uint64_t a = s.loopHead; a >= im.textLo && s.loopHead - a < 0x400; a -= 4)
        if (Dec::isSubSpImm(d.w(a))) { s.reclaimFn = a; break; }
    if (!s.reclaimFn) return fail("reclaim entry not found");
    { const uint32_t prev = d.w(s.reclaimFn - 4);
      if (!(Dec::isBL(prev) || Dec::isB(prev) || Dec::isRet(prev))) return fail("reclaim entry not at a function boundary"); }
    // 5) first bl in the pass = minimum-epoch call (reset site); then the free-list lock: adrp+add xQ = J; ...; bl LOCK; ldr [xQ,#8]
    uint64_t jLock = 0;
    for (uint64_t a = s.reclaimFn; a < s.loopHead; a += 4) {
        const uint32_t x = d.w(a);
        if (!Dec::isBL(x)) continue;
        if (!s.resetCall) { s.resetCall = a; s.wReset = x; s.minEpochFn = Dec::brTarget(a, x); continue; }
        if (!s.lockFn) {   // second bl: the lock of the free list; x0 came from a register holding adrp+add J
            s.lockFn = Dec::brTarget(a, x);
            for (uint64_t b = a - 4; b > s.resetCall && a - b <= 32; b -= 4) {
                const uint32_t y = d.w(b);
                if (Dec::isAddXimm(y)) { const uint64_t t = d.adrpAdd(b, Dec::rd(y)); if (t) { jLock = t; break; } }
            }
        }
    }
    if (!s.resetCall || !s.lockFn || !jLock) return fail("pass prologue (min-epoch call, list lock) not in shape");
    if (jLock + 8 != s.freeListHead) return fail("list lock and free-list head disagree");
    // 6) the lock routine takes the lock with casa on [x0]; the min-epoch routine locks with it and tail-calls UNLOCK (swpl wzr)
    { bool cas = false; for (int k = 0; k < 10; k++) cas |= Dec::isCasaW(d.w(s.lockFn + 4 * k)); if (!cas) return fail("lock routine has no casa"); }
    { bool lk = false; uint64_t un = 0;
      for (int k = 0; k < 24; k++) {
          const uint64_t a = s.minEpochFn + 4 * k; const uint32_t x = d.w(a);
          if (Dec::isBL(x) && Dec::brTarget(a, x) == s.lockFn) lk = true;
          if (Dec::isB(x)) { un = Dec::brTarget(a, x); break; }
      }
      if (!lk || !un) return fail("min-epoch routine not lock/compute/unlock");
      bool sw = false; for (int k = 0; k < 10; k++) sw |= Dec::isSwplWzr(d.w(un + 4 * k));
      if (!sw) return fail("unlock routine has no swpl wzr");
      s.unlockFn = un; }
    // 7) allocator grow site: add w20,w20,#7; and w0,w20,#~7; bl F; mov x21,x0; cbnz x0,GOT; mov x0,x19; bl GROW;
    //    and w1,w20,#~7; bl A; mov x21,x0  (registers are fixed: the stub relies on x19/w20/x21)
    hits.clear();
    for (uint64_t a = im.textLo; a + 40 <= im.textHi; a += 4) {
        if (!Dec::isAddW7(d.w(a), 20) || !Dec::isAndNot7(d.w(a + 4), 0, 20) || !Dec::isBL(d.w(a + 8))) continue;
        if (d.w(a + 12) != 0xAA0003F5U || !Dec::isCBNZx(d.w(a + 16)) || Dec::rd(d.w(a + 16)) != 0) continue;
        if (d.w(a + 20) != 0xAA1303E0U || !Dec::isBL(d.w(a + 24)) || !Dec::isAndNot7(d.w(a + 28), 1, 20)) continue;
        if (!Dec::isBL(d.w(a + 32)) || d.w(a + 36) != 0xAA0003F5U) continue;
        hits.push_back(a);
    }
    if (hits.size() != 1) return fail(hits.empty() ? "allocator grow site not found" : "allocator grow site not unique");
    const uint64_t G = hits[0];
    s.bestFitFn = Dec::brTarget(G + 8, d.w(G + 8));
    s.growCall = G + 24; s.wGrow = d.w(s.growCall); s.growFn = Dec::brTarget(s.growCall, s.wGrow);
    s.allocResume = G + 36;
    if (Dec::imm19Target(G + 16, d.w(G + 16)) != G + 40) return fail("allocator success branch out of shape");
    // 8) before the site: mov x0,x19; bl RECLAIM; adrp+add x0 = H; mov x1,x19; bl LOCK  (heap lock H)
    { const uint32_t bl1 = d.w(G - 4), mv = d.w(G - 8);
      if (!Dec::isBL(bl1) || Dec::brTarget(G - 4, bl1) != s.lockFn || mv != 0xAA1303E1U) return fail("heap re-lock before the site not in shape");
      s.heapLock = d.adrpAdd(G - 12, 0);
      const uint32_t blr = d.w(G - 20), mv0 = d.w(G - 24);
      if (!s.heapLock || !Dec::isBL(blr) || Dec::brTarget(G - 20, blr) != s.reclaimFn || mv0 != 0xAA1303E0U)
          return fail("allocator does not call this reclaim before the site"); }
    if (s.heapLock < im.dataLo || s.heapLock >= im.dataHi) return fail("heap lock not in __DATA");
    // 9) grow allocates the 128 MB chunk
    { bool c = false; for (int k = 0; k < 200; k++) c |= Dec::isMovz128M(d.w(s.growFn + 4 * k)); if (!c) return fail("grow routine has no 128 MB constant"); }
    // 10) the best-fit routine is the one the allocator used first (same F before the reclaim call)
    { bool f = false; for (uint64_t a = G - 64; a < G - 20; a += 4) { const uint32_t x = d.w(a); f |= Dec::isBL(x) && Dec::brTarget(a, x) == s.bestFitFn; }
      if (!f) return fail("best-fit routine not called before reclaim"); }
    // 11) free space: zero padding after the last __TEXT section, zero tail of __DATA
    s.padLo = (im.lastTextSect + 0x3FF) & ~0x3FFULL; s.padHi = im.textSegEnd;
    s.stateLo = (im.lastDataSect + 0xFFF) & ~0xFFFULL; s.stateHi = im.dataHi;
    if (s.padHi < s.padLo + 0x2000 || !allZero(im, s.padLo, s.padHi)) return fail("no zero __TEXT padding of >= 8 KB");
    if (s.stateHi < s.stateLo + 0x1000) return fail("no zero __DATA tail of >= 4 KB");
    if (s.stateLo + 0x1000 <= im.size && !allZero(im, s.stateLo, s.stateLo + 0x1000)) return fail("__DATA tail not zero");
    return true;
}

}  // namespace reclaimloc
