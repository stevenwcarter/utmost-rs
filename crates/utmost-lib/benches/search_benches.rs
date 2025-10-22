use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use utmost_lib::search::BoyerMoore;

fn search_forward_benchmark(c: &mut Criterion) {
    c.bench_function("search_forward", |b| {
        let bm = BoyerMoore::new(b"pattern", false, utmost_lib::SearchType::Forward);
        let mut search_bytes = vec![0u8; 512];
        search_bytes.extend_from_slice(b"This is a test string with a pattern inside it.");
        b.iter(|| bm.search_forward(black_box(search_bytes.as_slice()), black_box(0)));
    });
}

criterion_group!(benches, search_forward_benchmark);
criterion_main!(benches);
