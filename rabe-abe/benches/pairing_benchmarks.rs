//! Benchmarks for pairing and group operations
//!
//! Run with: cargo bench --bench pairing_benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::thread_rng;

fn bench_fr_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fr (Scalar Field)");
    let mut rng = thread_rng();

    let a = Fr::random(&mut rng);
    let b = Fr::random(&mut rng);

    group.bench_function("random", |bencher| {
        bencher.iter(|| Fr::random(&mut thread_rng()))
    });

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a) + black_box(b))
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a) - black_box(b))
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a) * black_box(b))
    });

    group.bench_function("inverse", |bencher| {
        bencher.iter(|| black_box(a).inverse())
    });

    group.bench_function("pow", |bencher| {
        bencher.iter(|| black_box(a).pow(&b))
    });

    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(a).into_bytes())
    });

    let bytes = a.into_bytes();
    group.bench_function("deserialize", |bencher| {
        bencher.iter(|| Fr::from_slice(black_box(&bytes)))
    });

    group.finish();
}

fn bench_g1_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("G1");
    let mut rng = thread_rng();

    let p = G1::random(&mut rng);
    let q = G1::random(&mut rng);
    let s = Fr::random(&mut rng);

    group.bench_function("random", |bencher| {
        bencher.iter(|| G1::random(&mut thread_rng()))
    });

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(p) + black_box(q))
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(p) - black_box(q))
    });

    group.bench_function("scalar_mul", |bencher| {
        bencher.iter(|| black_box(p) * black_box(s))
    });

    group.bench_function("neg", |bencher| {
        bencher.iter(|| -black_box(p))
    });

    group.bench_function("normalize", |bencher| {
        bencher.iter(|| black_box(p).normalize())
    });

    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(p).into_bytes())
    });

    let bytes = p.into_bytes();
    group.bench_function("deserialize", |bencher| {
        bencher.iter(|| G1::from_slice(black_box(&bytes)))
    });

    group.bench_function("hash_to_curve", |bencher| {
        let data = b"benchmark test data";
        bencher.iter(|| G1::hash_to_curve(black_box(data)))
    });

    group.finish();
}

fn bench_g2_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("G2");
    let mut rng = thread_rng();

    let p = G2::random(&mut rng);
    let q = G2::random(&mut rng);
    let s = Fr::random(&mut rng);

    group.bench_function("random", |bencher| {
        bencher.iter(|| G2::random(&mut thread_rng()))
    });

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(p) + black_box(q))
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(p) - black_box(q))
    });

    group.bench_function("scalar_mul", |bencher| {
        bencher.iter(|| black_box(p) * black_box(s))
    });

    group.bench_function("neg", |bencher| {
        bencher.iter(|| -black_box(p))
    });

    group.bench_function("normalize", |bencher| {
        bencher.iter(|| black_box(p).normalize())
    });

    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(p).into_bytes())
    });

    let bytes = p.into_bytes();
    group.bench_function("deserialize", |bencher| {
        bencher.iter(|| G2::from_slice(black_box(&bytes)))
    });

    group.bench_function("hash_to_curve", |bencher| {
        let data = b"benchmark test data";
        bencher.iter(|| G2::hash_to_curve(black_box(data)))
    });

    group.finish();
}

fn bench_gt_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Gt (Target Group)");
    let mut rng = thread_rng();

    let g1 = G1::random(&mut rng);
    let g2 = G2::random(&mut rng);
    let gt = pairing(g1, g2);
    let gt2 = pairing(G1::random(&mut rng), G2::random(&mut rng));
    let s = Fr::random(&mut rng);

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(gt) * black_box(gt2))
    });

    group.bench_function("pow", |bencher| {
        bencher.iter(|| black_box(gt).pow(&s))
    });

    group.bench_function("inverse", |bencher| {
        bencher.iter(|| black_box(gt).inverse())
    });

    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(gt).into_bytes())
    });

    let bytes = gt.into_bytes();
    group.bench_function("deserialize", |bencher| {
        bencher.iter(|| Gt::from_slice(black_box(&bytes)))
    });

    group.finish();
}

fn bench_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pairing");
    let mut rng = thread_rng();

    let g1 = G1::random(&mut rng);
    let g2 = G2::random(&mut rng);

    group.bench_function("single", |bencher| {
        bencher.iter(|| pairing(black_box(g1), black_box(g2)))
    });

    // Benchmark multi-pairing (product of pairings)
    for n in [2, 4, 8, 16].iter() {
        let g1s: Vec<G1> = (0..*n).map(|_| G1::random(&mut rng)).collect();
        let g2s: Vec<G2> = (0..*n).map(|_| G2::random(&mut rng)).collect();

        group.bench_with_input(BenchmarkId::new("product", n), n, |bencher, _| {
            bencher.iter(|| {
                let mut result = pairing(g1s[0], g2s[0]);
                for i in 1..g1s.len() {
                    result = result * pairing(g1s[i], g2s[i]);
                }
                result
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_fr_operations,
    bench_g1_operations,
    bench_g2_operations,
    bench_gt_operations,
    bench_pairing,
);

criterion_main!(benches);
