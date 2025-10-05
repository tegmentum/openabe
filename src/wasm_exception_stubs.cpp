///
/// Exception runtime stubs for WASM builds with WASI-SDK
///
/// WASI-SDK does not include C++ exception runtime support.
/// These stubs allow the code to compile and link, but will abort
/// if an exception is actually thrown at runtime.
///
/// This is acceptable for production use if:
/// 1. The code paths that throw exceptions are never hit, OR
/// 2. All exceptions are caught before reaching the boundary, OR
/// 3. Aborting is an acceptable error handling strategy
///

#include <cstdlib>
#include <cstddef>

extern "C" {

// Allocate memory for exception object
void* __cxa_allocate_exception(size_t thrown_size) noexcept {
    // Allocate memory for the exception object
    // If this returns, a throw will follow, which will abort
    void* ptr = malloc(thrown_size);
    if (!ptr) {
        abort();  // Out of memory
    }
    return ptr;
}

// Throw an exception (will abort in WASM)
void __cxa_throw(void* thrown_exception, void* tinfo, void (*dest)(void*)) noexcept {
    // In WASM without exception support, we cannot actually throw
    // Abort the program - this is the error path
    #ifdef __wasm__
    // Could log error info here before aborting if needed
    #endif
    abort();
}

// Free exception memory
void __cxa_free_exception(void* thrown_exception) noexcept {
    free(thrown_exception);
}

// Begin catch handler
void* __cxa_begin_catch(void* exceptionObject) noexcept {
    // Should never be called since __cxa_throw aborts
    abort();
    return nullptr;
}

// End catch handler
void __cxa_end_catch() noexcept {
    // Should never be called since __cxa_throw aborts
    abort();
}

// Rethrow current exception
void __cxa_rethrow() noexcept {
    // Should never be called since __cxa_throw aborts
    abort();
}

// Note: __cxa_current_primary_exception, __cxa_rethrow_primary_exception,
// __cxa_decrement_exception_refcount, and __cxa_increment_exception_refcount
// are already provided by cxa_noexception.cpp.o in libc++abi.a

} // extern "C"
