# OnionPIR browser WASM provenance

The checked-in OnionPIR browser artifacts are generated from
`Bitcoin-PIR/OnionPIRv2-fork` commit
`3f815ba86bc8cb2db5d892a006c1ee7fcbaf7e4b` plus the strict-CSP build
change in [OnionPIRv2-fork PR #3](https://github.com/Bitcoin-PIR/OnionPIRv2-fork/pull/3)
(`0d8b556`).

Build environment and command used for the current artifacts:

```text
Emscripten 5.0.7
cd wasm
EMSDK_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 ./build.sh --clean
```

The source build pins `DYNAMIC_EXECUTION=0` and `EMBIND_AOT=1`; the shipped
loader must contain neither `eval(...)` nor `new Function`. The BitcoinPIR
production build gate initializes the generated embind module and fails if
dynamic execution reappears.

SHA-256:

```text
1aba78be3752fe0697729d58a0af52a8715fb0646e24cb62e40cdc6b31f90246  onionpir_client.mjs
3c223e79fc3fb1f786fe9688d0505483f06c1dd62593e99716868923e670a7e8  onionpir_client.wasm
```

The strict-CSP rebuild changed only the JavaScript loader. The WebAssembly
module hash is identical to the pre-CSP artifact.
