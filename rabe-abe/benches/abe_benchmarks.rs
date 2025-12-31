//! Benchmarks for ABE schemes
//!
//! Run with: cargo bench --bench abe_benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use rabe_abe::schemes::{waters, waters_cca, gpsw, ac17, bsw};
use rabe_abe::lsss::{PolicyNode, LsssMatrix};
use rand::thread_rng;

// Test message for encryption benchmarks
const TEST_MESSAGE: &[u8] = b"Benchmark test message for ABE encryption";

// Generate attribute lists of various sizes
fn make_attributes(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("attr{}", i)).collect()
}

// Generate AND policy with n attributes
fn make_and_policy_str(n: usize) -> String {
    let attrs: Vec<String> = (0..n).map(|i| format!("attr{}", i)).collect();
    format!("({})", attrs.join(" AND "))
}

// Generate OR policy with n attributes
fn make_or_policy_str(n: usize) -> String {
    let attrs: Vec<String> = (0..n).map(|i| format!("attr{}", i)).collect();
    format!("({})", attrs.join(" OR "))
}

// Parse policy string to PolicyNode
fn make_and_policy(n: usize) -> PolicyNode {
    waters::parse_policy(&make_and_policy_str(n)).unwrap()
}

fn make_or_policy(n: usize) -> PolicyNode {
    waters::parse_policy(&make_or_policy_str(n)).unwrap()
}

// ============================================================================
// Waters CP-ABE (CPA) Benchmarks
// ============================================================================

fn bench_waters_cpa(c: &mut Criterion) {
    let mut group = c.benchmark_group("Waters CP-ABE (CPA)");
    let mut rng = thread_rng();

    // Setup
    let (mpk, msk) = waters::setup(&mut rng);

    group.bench_function("setup", |bencher| {
        bencher.iter(|| waters::setup(&mut thread_rng()))
    });

    // Keygen with varying attribute counts
    for n in [1, 5, 10, 20].iter() {
        let attrs = make_attributes(*n);
        group.bench_with_input(BenchmarkId::new("keygen", n), n, |bencher, _| {
            bencher.iter(|| waters::keygen(&mut thread_rng(), &mpk, &msk, black_box(&attrs)))
        });
    }

    // Encrypt with varying policy sizes (AND)
    for n in [1, 2, 4, 8].iter() {
        let policy = make_and_policy(*n);
        group.throughput(Throughput::Bytes(TEST_MESSAGE.len() as u64));
        group.bench_with_input(BenchmarkId::new("encrypt_and", n), n, |bencher, _| {
            bencher.iter(|| {
                waters::encrypt(&mut thread_rng(), &mpk, black_box(&policy), black_box(TEST_MESSAGE))
            })
        });
    }

    // Encrypt with varying policy sizes (OR)
    for n in [2, 4, 8].iter() {
        let policy = make_or_policy(*n);
        group.bench_with_input(BenchmarkId::new("encrypt_or", n), n, |bencher, _| {
            bencher.iter(|| {
                waters::encrypt(&mut thread_rng(), &mpk, black_box(&policy), black_box(TEST_MESSAGE))
            })
        });
    }

    // Decrypt benchmarks
    for n in [1, 2, 4, 8].iter() {
        let policy = make_and_policy(*n);
        let attrs = make_attributes(*n);
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();
        let ct = waters::encrypt(&mut rng, &mpk, &policy, TEST_MESSAGE).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt_and", n), n, |bencher, _| {
            bencher.iter(|| waters::decrypt(black_box(&mpk), black_box(&sk), black_box(&ct)))
        });
    }

    group.finish();
}

// ============================================================================
// Waters CP-ABE (CCA) Benchmarks
// ============================================================================

fn bench_waters_cca(c: &mut Criterion) {
    let mut group = c.benchmark_group("Waters CP-ABE (CCA)");
    let mut rng = thread_rng();

    // CCA uses same setup/keygen as CPA
    let (mpk, msk) = waters::setup(&mut rng);

    // Encrypt/Decrypt with CCA wrapper
    for n in [1, 2, 4].iter() {
        let policy = make_and_policy(*n);
        let attrs = make_attributes(*n);
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        group.bench_with_input(BenchmarkId::new("encrypt", n), n, |bencher, _| {
            bencher.iter(|| {
                waters_cca::encrypt(&mut thread_rng(), &mpk, black_box(&policy), black_box(TEST_MESSAGE))
            })
        });

        let ct = waters_cca::encrypt(&mut rng, &mpk, &policy, TEST_MESSAGE).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", n), n, |bencher, _| {
            bencher.iter(|| waters_cca::decrypt(black_box(&mpk), black_box(&sk), black_box(&ct)))
        });
    }

    group.finish();
}

// ============================================================================
// GPSW KP-ABE Benchmarks
// ============================================================================

fn bench_gpsw(c: &mut Criterion) {
    let mut group = c.benchmark_group("GPSW KP-ABE");
    let mut rng = thread_rng();

    // Setup
    group.bench_function("setup", |bencher| {
        bencher.iter(|| gpsw::setup(&mut thread_rng()))
    });

    let (mpk, msk) = gpsw::setup(&mut rng);

    // Keygen with varying policy sizes (KP-ABE: policy in key)
    for n in [1, 2, 4, 8].iter() {
        let policy = make_and_policy(*n);
        group.bench_with_input(BenchmarkId::new("keygen", n), n, |bencher, _| {
            bencher.iter(|| gpsw::keygen(&mut thread_rng(), &mpk, &msk, black_box(&policy)))
        });
    }

    // Encrypt with varying attribute counts (KP-ABE: attributes in ciphertext)
    for n in [1, 5, 10].iter() {
        let attrs = make_attributes(*n);
        group.bench_with_input(BenchmarkId::new("encrypt", n), n, |bencher, _| {
            bencher.iter(|| {
                gpsw::encrypt(&mut thread_rng(), &mpk, black_box(&attrs), black_box(TEST_MESSAGE))
            })
        });
    }

    // Decrypt
    let policy = make_and_policy(2);
    let attrs = make_attributes(2);
    let sk = gpsw::keygen(&mut rng, &mpk, &msk, &policy).unwrap();
    let ct = gpsw::encrypt(&mut rng, &mpk, &attrs, TEST_MESSAGE).unwrap();

    group.bench_function("decrypt", |bencher| {
        bencher.iter(|| gpsw::decrypt(black_box(&mpk), black_box(&sk), black_box(&ct)))
    });

    group.finish();
}

// ============================================================================
// AC17 CP-ABE Benchmarks
// ============================================================================

fn bench_ac17(c: &mut Criterion) {
    let mut group = c.benchmark_group("AC17 CP-ABE");
    let mut rng = thread_rng();

    let (mpk, msk) = ac17::setup(&mut rng);

    group.bench_function("setup", |bencher| {
        bencher.iter(|| ac17::setup(&mut thread_rng()))
    });

    // Keygen
    for n in [1, 5, 10, 20].iter() {
        let attrs = make_attributes(*n);
        group.bench_with_input(BenchmarkId::new("keygen", n), n, |bencher, _| {
            bencher.iter(|| ac17::keygen(&mut thread_rng(), &mpk, &msk, black_box(&attrs)))
        });
    }

    // Encrypt
    for n in [1, 2, 4, 8].iter() {
        let policy = make_and_policy(*n);
        group.bench_with_input(BenchmarkId::new("encrypt", n), n, |bencher, _| {
            bencher.iter(|| {
                ac17::encrypt(&mut thread_rng(), &mpk, black_box(&policy), black_box(TEST_MESSAGE))
            })
        });
    }

    // Decrypt
    for n in [1, 2, 4, 8].iter() {
        let policy = make_and_policy(*n);
        let attrs = make_attributes(*n);
        let sk = ac17::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();
        let ct = ac17::encrypt(&mut rng, &mpk, &policy, TEST_MESSAGE).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt", n), n, |bencher, _| {
            bencher.iter(|| ac17::decrypt(black_box(&mpk), black_box(&sk), black_box(&ct)))
        });
    }

    group.finish();
}

// ============================================================================
// BSW CP-ABE Benchmarks
// ============================================================================

fn bench_bsw(c: &mut Criterion) {
    let mut group = c.benchmark_group("BSW CP-ABE");
    let mut rng = thread_rng();

    let (mpk, msk) = bsw::setup(&mut rng);

    group.bench_function("setup", |bencher| {
        bencher.iter(|| bsw::setup(&mut thread_rng()))
    });

    // Keygen
    for n in [1, 5, 10].iter() {
        let attrs = make_attributes(*n);
        group.bench_with_input(BenchmarkId::new("keygen", n), n, |bencher, _| {
            bencher.iter(|| bsw::keygen(&mut thread_rng(), &mpk, &msk, black_box(&attrs)))
        });
    }

    // Encrypt (BSW takes policy as string)
    for n in [1, 2, 4].iter() {
        let policy = make_and_policy_str(*n);
        group.bench_with_input(BenchmarkId::new("encrypt", n), n, |bencher, _| {
            bencher.iter(|| {
                bsw::encrypt(&mut thread_rng(), &mpk, black_box(&policy), black_box(TEST_MESSAGE))
            })
        });
    }

    // Decrypt
    let policy = "(attr0 AND attr1)";
    let attrs = make_attributes(2);
    let sk = bsw::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();
    let ct = bsw::encrypt(&mut rng, &mpk, policy, TEST_MESSAGE).unwrap();

    group.bench_function("decrypt", |bencher| {
        bencher.iter(|| bsw::decrypt(black_box(&sk), black_box(&ct)))
    });

    group.finish();
}

// ============================================================================
// LSSS Benchmarks
// ============================================================================

fn bench_lsss(c: &mut Criterion) {
    let mut group = c.benchmark_group("LSSS");

    // Policy parsing
    for n in [2, 4, 8, 16].iter() {
        let policy_str = make_and_policy_str(*n);
        group.bench_with_input(BenchmarkId::new("parse_and", n), n, |bencher, _| {
            bencher.iter(|| waters::parse_policy(black_box(&policy_str)))
        });
    }

    // LSSS matrix construction
    for n in [2, 4, 8, 16].iter() {
        let policy = make_and_policy(*n);
        group.bench_with_input(BenchmarkId::new("matrix_and", n), n, |bencher, _| {
            bencher.iter(|| LsssMatrix::from_policy(black_box(&policy)))
        });
    }

    // Complex policy (nested AND/OR)
    let complex_policy = "((attr0 AND attr1) OR (attr2 AND attr3))";
    group.bench_function("parse_complex", |bencher| {
        bencher.iter(|| waters::parse_policy(black_box(complex_policy)))
    });

    let complex_node = waters::parse_policy(complex_policy).unwrap();
    group.bench_function("matrix_complex", |bencher| {
        bencher.iter(|| LsssMatrix::from_policy(black_box(&complex_node)))
    });

    // Threshold policy
    let threshold_policy = "(2 of attr0, attr1, attr2, attr3)";
    group.bench_function("parse_threshold", |bencher| {
        bencher.iter(|| waters::parse_policy(black_box(threshold_policy)))
    });

    let threshold_node = waters::parse_policy(threshold_policy).unwrap();
    group.bench_function("matrix_threshold", |bencher| {
        bencher.iter(|| LsssMatrix::from_policy(black_box(&threshold_node)))
    });

    group.finish();
}

// ============================================================================
// Serialization Benchmarks
// ============================================================================

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialization");
    let mut rng = thread_rng();

    // Waters CPA
    let (mpk, msk) = waters::setup(&mut rng);
    let attrs = make_attributes(5);
    let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();
    let policy = make_and_policy(3);
    let ct = waters::encrypt(&mut rng, &mpk, &policy, TEST_MESSAGE).unwrap();

    // Serialize
    group.bench_function("waters_mpk_serialize", |bencher| {
        bencher.iter(|| serde_json::to_vec(black_box(&mpk)))
    });

    group.bench_function("waters_sk_serialize", |bencher| {
        bencher.iter(|| serde_json::to_vec(black_box(&sk)))
    });

    group.bench_function("waters_ct_serialize", |bencher| {
        bencher.iter(|| serde_json::to_vec(black_box(&ct)))
    });

    // Deserialize
    let mpk_bytes = serde_json::to_vec(&mpk).unwrap();
    let sk_bytes = serde_json::to_vec(&sk).unwrap();
    let ct_bytes = serde_json::to_vec(&ct).unwrap();

    group.bench_function("waters_mpk_deserialize", |bencher| {
        bencher.iter(|| serde_json::from_slice::<waters::Mpk>(black_box(&mpk_bytes)))
    });

    group.bench_function("waters_sk_deserialize", |bencher| {
        bencher.iter(|| serde_json::from_slice::<waters::SecretKey>(black_box(&sk_bytes)))
    });

    group.bench_function("waters_ct_deserialize", |bencher| {
        bencher.iter(|| serde_json::from_slice::<waters::FullCiphertext>(black_box(&ct_bytes)))
    });

    // CBOR serialization
    group.bench_function("waters_ct_cbor_serialize", |bencher| {
        bencher.iter(|| {
            let mut buf = Vec::new();
            ciborium::into_writer(black_box(&ct), &mut buf).unwrap();
            buf
        })
    });

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&ct, &mut cbor_buf).unwrap();
    group.bench_function("waters_ct_cbor_deserialize", |bencher| {
        bencher.iter(|| {
            ciborium::from_reader::<waters::FullCiphertext, _>(black_box(&cbor_buf[..]))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_waters_cpa,
    bench_waters_cca,
    bench_gpsw,
    bench_ac17,
    bench_bsw,
    bench_lsss,
    bench_serialization,
);

criterion_main!(benches);
