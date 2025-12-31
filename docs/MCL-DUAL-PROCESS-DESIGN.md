# MCL Dual-Process Architecture Design

## Problem Statement

MCL BN254 (pairings) requires `MCL_FP_BIT=256`, while MCL ECDSA (secp256k1) requires `MCL_FP_BIT=384`. These cannot coexist in a single process.

## Solution: Separate Process Architecture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Main Process (OpenABE Application)                          │
│                                                              │
│ ┌────────────────────┐        ┌──────────────────────────┐ │
│ │  ABE Operations    │        │  ECDSA Proxy             │ │
│ │                    │        │  (IPC Client)            │ │
│ │  MCL BN254         │        │                          │ │
│ │  (MCL_FP_BIT=256) │        │  - Serializes requests   │ │
│ │                    │        │  - Sends to worker       │ │
│ │  - Pairings        │        │  - Receives responses    │ │
│ │  - G1, G2, GT ops  │        │                          │ │
│ └────────────────────┘        └──────────────────────────┘ │
│                                           │                  │
└───────────────────────────────────────────┼──────────────────┘
                                            │
                                    IPC Channel
                              (Unix Socket / Pipe)
                                            │
┌───────────────────────────────────────────┼──────────────────┐
│ ECDSA Worker Process                      │                  │
│                                           │                  │
│ ┌─────────────────────────────────────────▼────────────────┐ │
│ │  ECDSA Service (IPC Server)                              │ │
│ │                                                           │ │
│ │  MCL ECDSA (MCL_FP_BIT=384)                             │ │
│ │                                                           │ │
│ │  - Receives requests                                     │ │
│ │  - Performs ECDSA operations                            │ │
│ │  - Returns results                                       │ │
│ │                                                           │ │
│ │  Operations:                                             │ │
│ │  • keygen(curve_id) -> (public_key, private_key)       │ │
│ │  • sign(private_key, message) -> signature              │ │
│ │  • verify(public_key, message, signature) -> bool       │ │
│ └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Components

#### 1. ECDSA Worker Binary (`oabe_ecdsa_worker`)

```bash
# Standalone executable
./oabe_ecdsa_worker --socket /tmp/oabe_ecdsa.sock
```

**Features:**
- Compiled with MCL ECDSA (`MCL_FP_BIT=384`)
- Listens on Unix domain socket
- Stateless request/response protocol
- Can be spawned on-demand or run as daemon

#### 2. IPC Protocol (Message Format)

```c
// Request format
struct ECDSARequest {
    uint32_t request_id;      // For matching responses
    uint8_t  operation;       // KEYGEN=1, SIGN=2, VERIFY=3
    uint8_t  curve_id;        // Currently only secp256k1
    uint16_t data_len;        // Length of operation-specific data
    uint8_t  data[];          // Variable-length data
};

// Response format
struct ECDSAResponse {
    uint32_t request_id;      // Matches request
    uint8_t  status;          // SUCCESS=0, ERROR=1
    uint16_t data_len;        // Length of result data
    uint8_t  data[];          // Variable-length result
};

// Operation-specific data formats:

// KEYGEN: Empty data
// Response: DER-encoded public key (33 bytes compressed) + private key (32 bytes)

// SIGN: private_key (32 bytes) + message (N bytes)
// Response: signature (64 bytes)

// VERIFY: public_key (33 bytes) + message (N bytes) + signature (64 bytes)
// Response: single byte (0=invalid, 1=valid)
```

#### 3. ECDSA Proxy Client (In Main Process)

```cpp
// zecdsa_mcl_proxy.cpp - IPC client implementation
class MCLECDSAProxy {
private:
    int socket_fd;
    uint32_t next_request_id;
    std::string socket_path;

    // Connection management
    bool connect();
    void disconnect();
    bool ensureConnected();

    // Low-level IPC
    bool sendRequest(const ECDSARequest& req);
    bool recvResponse(ECDSAResponse& resp);

public:
    MCLECDSAProxy(const std::string& socket_path);
    ~MCLECDSAProxy();

    // High-level operations
    int keygen(uint8_t curve_id,
               uint8_t* public_key, size_t* pub_len,
               uint8_t* private_key, size_t* priv_len);

    int sign(const uint8_t* private_key, size_t priv_len,
             const uint8_t* message, size_t msg_len,
             uint8_t* signature, size_t* sig_len);

    int verify(const uint8_t* public_key, size_t pub_len,
               const uint8_t* message, size_t msg_len,
               const uint8_t* signature, size_t sig_len);
};
```

#### 4. Worker Process Management

```cpp
// ecdsa_worker_manager.cpp
class ECDSAWorkerManager {
private:
    pid_t worker_pid;
    std::string socket_path;
    bool auto_spawn;

public:
    ECDSAWorkerManager();
    ~ECDSAWorkerManager();

    // Lifecycle management
    bool startWorker();
    bool stopWorker();
    bool isWorkerRunning();

    // Get proxy for communication
    MCLECDSAProxy* getProxy();

    // Auto-restart on failure
    void setupHealthCheck();
};
```

### Pros and Cons

#### Advantages ✅

1. **Complete Isolation**: Each process has its own MCL instance
2. **No Compile-Time Conflicts**: Different `MCL_FP_BIT` in each binary
3. **Fault Tolerance**: Worker crash doesn't affect main process
4. **Security**: Can sandbox worker process with lower privileges
5. **Performance**: Can use multiple workers for parallelism
6. **Debugging**: Easy to debug/profile each component separately

#### Disadvantages ❌

1. **IPC Overhead**:
   - Each ECDSA operation requires IPC round-trip
   - ~50-500 microseconds per operation (vs ~1-10 μs in-process)

2. **Complexity**:
   - More code to maintain
   - Process lifecycle management
   - Error handling for IPC failures
   - Socket/pipe handling

3. **Deployment**:
   - Additional binary to distribute
   - Need to manage worker process lifecycle
   - Configuration for socket paths, permissions

4. **Memory**:
   - Two separate process address spaces
   - Worker process overhead (~10-20 MB)

### Performance Analysis

**Latency Breakdown:**

```
In-Process OpenSSL ECDSA:
├─ sign():   ~50 μs
├─ verify(): ~150 μs
└─ Total:    ~200 μs per sign+verify cycle

With IPC to MCL Worker:
├─ Serialize request:     ~5 μs
├─ Unix socket write:     ~10 μs
├─ Worker processes:      ~50 μs (sign)
├─ Unix socket read:      ~10 μs
├─ Deserialize response:  ~5 μs
├─ Round-trip overhead:   ~80 μs
└─ Total:                 ~130 μs per operation

Total overhead: ~60 μs per operation (40-60% slower)
```

**When This Is Acceptable:**

- PKSIG operations are infrequent (< 1000/sec)
- Correctness > performance (using pure MCL stack)
- Already using network/disk I/O (dominated by those costs)

**When This Is Problematic:**

- High-frequency signing (> 10,000/sec)
- Real-time requirements (< 1ms latency budgets)
- Embedded systems (limited process overhead)

### Alternative: Approach 3B - Dynamic Library Isolation

```
Main Process
├─ dlopen("libmcl_bn254.so") with RTLD_LOCAL
│  └─ Isolated namespace for BN254
├─ dlopen("libmcl_ecdsa.so") with RTLD_LOCAL
│  └─ Isolated namespace for ECDSA
└─ Symbol conflicts avoided by namespace isolation
```

**Key Issue**: This approach **still won't work** because:

1. **Global State**: MCL uses global variables internally
2. **Memory Layout**: `MCL_FP_BIT` affects struct sizes
3. **Type Safety**: Same function names with different semantics
4. **Undefined Behavior**: Passing data between incompatible MCL instances

**Verdict**: Dynamic loading doesn't solve the fundamental incompatibility.

### Approach 3C: Microservice Architecture (Most Scalable)

```
┌─────────────────────┐
│  Main Application   │
│  (ABE + Orchestration)
│                     │
└──────────┬──────────┘
           │
      HTTP/gRPC
           │
    ┌──────▼──────┐
    │  ECDSA      │
    │  Service    │
    │  (MCL ECDSA)│
    └─────────────┘
```

**Features:**
- Network-based communication (HTTP REST or gRPC)
- Can scale horizontally (multiple ECDSA workers)
- Language-agnostic (worker could be in any language)
- Can run on different machines

**Pros:**
- Maximum flexibility and scalability
- Easy monitoring and metrics
- Built-in load balancing

**Cons:**
- Much higher latency (milliseconds vs microseconds)
- Network security considerations
- Operational complexity

## Recommended Implementation Path

### Phase 1: Stay with Hybrid (MCL + OpenSSL) ✅

**Current solution is optimal for most use cases:**
- MCL for pairings (what MCL is best at)
- OpenSSL for ECDSA (industry standard)
- No complexity, good performance
- **Already implemented and tested**

### Phase 2: If Pure MCL Stack Is Required

**Only implement separate process if:**
1. Regulatory requirement for pure MCL cryptography
2. MCL-specific features needed for ECDSA
3. Willing to accept 40-60% performance overhead

**Implementation steps:**
1. Build `oabe_ecdsa_worker` binary with MCL ECDSA
2. Implement Unix socket IPC protocol
3. Create `zecdsa_mcl_proxy.cpp` client
4. Add worker process management
5. Extensive testing of failure modes

### Phase 3: Microservice (If Distributed System)

**Only for large-scale deployments where:**
- Multiple services need ECDSA
- Already have microservice infrastructure
- Performance of individual operations less critical

## Code Example: Simple IPC Implementation

```cpp
// Minimal proof-of-concept for Unix socket IPC

// Worker side (in separate binary)
int main() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, "/tmp/oabe_ecdsa.sock");
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 5);

    // Initialize MCL ECDSA (MCL_FP_BIT=384)
    if (ecdsaInit() != 0) {
        fprintf(stderr, "Failed to init MCL ECDSA\n");
        return 1;
    }

    while (1) {
        int client = accept(sock, NULL, NULL);

        // Read request
        ECDSARequest req;
        read(client, &req, sizeof(req));

        // Process
        ECDSAResponse resp = {.request_id = req.request_id};

        switch (req.operation) {
        case OP_KEYGEN: {
            ecdsaSecretKey sk;
            ecdsaPublicKey pk;
            ecdsaSecretKeySetByCSPRNG(&sk);
            ecdsaGetPublicKey(&pk, &sk);

            resp.data_len = 33 + 32; // pub + priv
            ecdsaPublicKeySerializeCompressed(resp.data, 33, &pk);
            ecdsaSecretKeySerialize(resp.data + 33, 32, &sk);
            resp.status = 0;
            break;
        }
        case OP_SIGN: {
            // Deserialize key and message from req.data
            // Call ecdsaSign()
            // Serialize signature to resp.data
            break;
        }
        case OP_VERIFY: {
            // Deserialize key, message, sig from req.data
            // Call ecdsaVerify()
            // Set resp.status based on result
            break;
        }
        }

        // Send response
        write(client, &resp, sizeof(resp));
        close(client);
    }
}

// Client side (in main process)
int ecdsa_sign_via_worker(/* ... */) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, "/tmp/oabe_ecdsa.sock");
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    ECDSARequest req = {
        .request_id = get_next_id(),
        .operation = OP_SIGN,
        // ... fill in data
    };

    write(sock, &req, sizeof(req));

    ECDSAResponse resp;
    read(sock, &resp, sizeof(resp));

    close(sock);
    return resp.status;
}
```

## Conclusion

**For OpenABE:**

The separate process approach (3A) is **technically feasible** but adds significant complexity for marginal benefit. The current hybrid solution (MCL + OpenSSL) is superior because:

1. ✅ **Simple**: No IPC complexity
2. ✅ **Fast**: No IPC overhead
3. ✅ **Reliable**: No process management issues
4. ✅ **Proven**: OpenSSL ECDSA is battle-tested
5. ✅ **Standard**: Industry-standard ECDSA implementation

**Only implement separate process if:**
- Absolute requirement for pure MCL stack
- Performance overhead acceptable
- Team has resources for additional complexity

Otherwise, stick with the current working solution! 🎯
