///
/// WASM Mutex Stub Header
///
/// This file provides a no-op mutex implementation for WebAssembly builds.
/// WASM currently runs in a single-threaded environment, so mutex operations
/// are not needed. This stub allows code to compile without modification.
///

#ifndef __WASM_MUTEX_H__
#define __WASM_MUTEX_H__

#ifdef __wasm__

namespace std {
    // adopt_lock_t type for lock_guard constructor
    struct adopt_lock_t { };
    constexpr adopt_lock_t adopt_lock = adopt_lock_t();

    // No-op mutex implementation for single-threaded WASM environment
    class mutex {
    public:
        mutex() noexcept = default;
        ~mutex() = default;

        // Delete copy constructor and assignment operator
        mutex(const mutex&) = delete;
        mutex& operator=(const mutex&) = delete;

        // No-op lock/unlock operations for single-threaded WASM
        void lock() noexcept { }
        void unlock() noexcept { }
        bool try_lock() noexcept { return true; }
    };

    // No-op lock_guard implementation for RAII mutex locking
    template<typename Mutex>
    class lock_guard {
    public:
        typedef Mutex mutex_type;

        explicit lock_guard(Mutex& m) : mutex_(m) {
            mutex_.lock();
        }

        lock_guard(Mutex& m, adopt_lock_t) : mutex_(m) { }

        ~lock_guard() {
            mutex_.unlock();
        }

        lock_guard(const lock_guard&) = delete;
        lock_guard& operator=(const lock_guard&) = delete;

    private:
        Mutex& mutex_;
    };
}

#else
    // For non-WASM builds, use standard <mutex>
    #include <mutex>
#endif

#endif // __WASM_MUTEX_H__
