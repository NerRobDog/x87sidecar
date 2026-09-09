# Building x87sidecar for the dxmt-aoe4-pack

```
cmake -B build -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build -j8
```

`-DCMAKE_OSX_ARCHITECTURES=arm64` is required when cmake comes from an x86_64 Homebrew
(it would otherwise build x86_64 and fail on `arm_thread_state64_t`). Apple clang, deployment
target 14.0, Release with asserts as the project's CMakeLists insists. The flat `x87sidecar`
binary (ad-hoc signature, no entitlements) is what the Wine loader re-execs via
`AOELAB_SIDECAR_PATH`; the entitled variant is not needed by the pack.

Built for the pack on 2026-09-09 (M1 Pro, macOS 26.5.2): sha256
6c7801fb0a9f238146af2002dbd7228f352e8d4a09ead60accd915e2b1bae81e, 526560 bytes;
`--probe` reports `supported` on macOS 26.5.2 (M1 Pro, M5) and 26.6.2 (M2 Pro).
