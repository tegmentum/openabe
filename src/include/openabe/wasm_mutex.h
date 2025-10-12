///
/// WASM Mutex Compatibility Header
///
/// This file handles mutex support for WebAssembly builds.
/// Modern WASI SDK (24+) includes native <mutex> support with pthread,
/// while older versions need a no-op stub implementation.
///

#ifndef __WASM_MUTEX_H__
#define __WASM_MUTEX_H__

// WASI SDK 24+ with wasm32-wasi-threads has native mutex support
// Just use standard <mutex> for all builds now
#include <mutex>

#endif // __WASM_MUTEX_H__
