use crate::RttEstimator;
use std::time::Duration;

// Raw RTT and effective ACK delay, both in integer microseconds. These are
// explicit estimator inputs, not values inferred from browser packet spacing.
const INPUTS_MICROS: [(u64, u64); 5] = [
    (10_001, 0),
    (11_003, 200),
    (9_007, 0),
    (30_001, 2_000),
    (10_001, 0),
];

// Fixed outputs of the pinned QUICHE source oracle retained in
// design/audits/h3-timing-source-closure-20261012.md, not another estimator here.
const CHROME_TARGET_MICROS: [(u128, u128); 5] = [
    (10_001, 5_000),
    (10_101, 3_950),
    (9_964, 3_236),
    (12_219, 6_936),
    (11_942, 5_756),
];

fn observe_rtt_updates(chrome_quantization: bool) -> Vec<(Duration, Duration)> {
    let mut estimator =
        RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(chrome_quantization);
    assert!(estimator.sampled_rtt_inputs().is_none());
    INPUTS_MICROS
        .into_iter()
        .enumerate()
        .map(|(step, (raw_us, ack_delay_us))| {
            estimator.update(
                Duration::from_micros(ack_delay_us),
                Duration::from_micros(raw_us),
            );
            let (srtt, variation) = estimator.sampled_rtt_inputs().unwrap();
            eprintln!(
                "chrome_quantization={chrome_quantization} step={step} raw_rtt_us={raw_us} ack_delay_us={ack_delay_us} \
                 min_rtt_ns={} srtt_ns={} variation_ns={} \
                 srtt_whole_us={} variation_whole_us={} \
                 chrome_target_srtt_us={} chrome_target_variation_us={}",
                estimator.min().as_nanos(),
                srtt.as_nanos(),
                variation.as_nanos(),
                srtt.as_micros(),
                variation.as_micros(),
                CHROME_TARGET_MICROS[step].0,
                CHROME_TARGET_MICROS[step].1,
            );
            (srtt, variation)
        })
        .collect()
}

#[test]
fn pto_clock_legacy_estimator_matches_source_oracle() {
    let observed: Vec<_> = observe_rtt_updates(false)
        .into_iter()
        .map(|(srtt, variation)| (srtt.as_nanos(), variation.as_nanos()))
        .collect();
    assert_eq!(
        observed,
        [
            (10_001_000, 5_000_500),
            (10_101_250, 3_950_875),
            (9_964_468, 3_236_718),
            (12_219_034, 6_936_671),
            (11_941_779, 5_757_011),
        ],
        "the default production estimator must preserve its nanosecond recurrence"
    );
}

#[test]
fn pto_clock_chrome_source_target_comparison() {
    let observed: Vec<_> = observe_rtt_updates(true)
        .into_iter()
        .map(|(srtt, variation)| (srtt.as_micros(), variation.as_micros()))
        .collect();
    assert_eq!(
        observed, CHROME_TARGET_MICROS,
        "the opt-in recurrence must match the pinned Chrome source target"
    );
}

#[test]
fn pto_clock_chrome_rounds_each_smoothed_product_separately() {
    let mut chrome = RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
    let mut legacy = RttEstimator::new(Duration::from_millis(333));
    for estimator in [&mut chrome, &mut legacy] {
        estimator.update(Duration::ZERO, Duration::from_micros(4));
        estimator.update(Duration::ZERO, Duration::from_micros(4));
    }
    assert_eq!(chrome.get(), Duration::from_micros(5));
    assert_eq!(legacy.get(), Duration::from_micros(4));
    assert_eq!(
        chrome.sampled_rtt_inputs().unwrap().1,
        Duration::from_micros(1)
    );
}

#[test]
fn pto_clock_chrome_variation_uses_f32_while_smoothing_uses_f64() {
    let mut estimator =
        RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
    estimator.update(Duration::ZERO, Duration::from_micros(16_777_217));
    estimator.update(Duration::ZERO, Duration::from_micros(16_777_220));
    assert_eq!(
        estimator.sampled_rtt_inputs(),
        Some((
            Duration::from_micros(16_777_218),
            Duration::from_micros(6_291_457)
        )),
        "integer/f64 variation arithmetic would give 6291456; f32 smoothing would lose precision"
    );
}

#[test]
fn pto_clock_chrome_adapts_fractional_inputs_without_changing_raw_rtt_metrics() {
    let mut chrome = RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
    let mut legacy = RttEstimator::new(Duration::from_millis(333));
    let first = Duration::from_nanos(10_001_999);
    for estimator in [&mut chrome, &mut legacy] {
        estimator.update(Duration::from_micros(50_000), first);
    }
    assert_eq!(
        chrome.sampled_rtt_inputs(),
        Some((Duration::from_micros(10_001), Duration::from_micros(5_000)))
    );
    assert_eq!(
        legacy.sampled_rtt_inputs(),
        Some((first, Duration::from_nanos(5_000_999)))
    );
    assert_eq!(chrome.min(), first);
    assert_eq!(chrome.conservative(), first);

    let second = Duration::from_nanos(12_001_500);
    let ack_delay = Duration::from_nanos(2_000_999);
    for estimator in [&mut chrome, &mut legacy] {
        estimator.update(ack_delay, second);
    }
    assert_eq!(
        chrome.sampled_rtt_inputs(),
        Some((Duration::from_micros(10_001), Duration::from_micros(3_750)))
    );
    assert!(
        legacy.get() > chrome.get(),
        "the raw-ns ACK correction fails the minimum check here"
    );
    assert_eq!(chrome.min(), first);
    assert_eq!(
        chrome.conservative(),
        second,
        "loss consumers retain the latest raw Duration"
    );
}

#[test]
fn pto_clock_chrome_ack_delay_respects_minimum_and_cannot_underflow() {
    for delay in [Duration::from_micros(3_000), Duration::MAX] {
        let mut estimator =
            RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
        estimator.update(Duration::ZERO, Duration::from_micros(10_000));
        estimator.update(delay, Duration::from_micros(12_000));
        assert_eq!(
            estimator.sampled_rtt_inputs(),
            Some((Duration::from_micros(10_250), Duration::from_micros(4_250)))
        );
        assert_eq!(estimator.min(), Duration::from_micros(10_000));
    }
    let mut estimator =
        RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
    estimator.update(Duration::ZERO, Duration::from_micros(10_000));
    estimator.update(Duration::from_micros(9_000), Duration::from_micros(8_000));
    assert_eq!(
        estimator.sampled_rtt_inputs(),
        Some((Duration::from_micros(9_750), Duration::from_micros(4_250)))
    );
    assert_eq!(estimator.min(), Duration::from_micros(8_000));
}

#[test]
fn pto_clock_chrome_ignores_zero_or_unrepresentable_samples() {
    let initial = Duration::from_millis(333);
    let mut estimator = RttEstimator::new(initial).with_chrome_quantization(true);
    for invalid in [
        Duration::ZERO,
        Duration::from_nanos(999),
        Duration::from_micros(i64::MAX as u64),
        Duration::MAX,
    ] {
        estimator.update(Duration::ZERO, invalid);
        assert_eq!(estimator.sampled_rtt_inputs(), None);
        assert_eq!(estimator.min(), initial);
        assert_eq!(estimator.get(), initial);
    }
    estimator.update(Duration::MAX, Duration::from_micros(1));
    assert_eq!(
        estimator.sampled_rtt_inputs(),
        Some((Duration::from_micros(1), Duration::ZERO))
    );
    estimator.update(Duration::ZERO, Duration::MAX);
    assert_eq!(
        estimator.sampled_rtt_inputs(),
        Some((Duration::from_micros(1), Duration::ZERO))
    );
    assert_eq!(estimator.min(), Duration::from_micros(1));

    let mut maximum_initial = RttEstimator::new(Duration::MAX).with_chrome_quantization(true);
    maximum_initial.update(Duration::MAX, Duration::from_micros(1));
    assert_eq!(
        maximum_initial.sampled_rtt_inputs(),
        Some((Duration::from_micros(1), Duration::ZERO))
    );
}

#[test]
fn pto_clock_chrome_extreme_finite_inputs_do_not_wrap() {
    let mut estimator =
        RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(true);
    let large = Duration::from_micros(i64::MAX as u64 - 1);
    estimator.update(Duration::ZERO, large);
    estimator.update(Duration::ZERO, large);
    let (srtt, variation) = estimator.sampled_rtt_inputs().unwrap();
    assert!(
        srtt >= large / 2,
        "float conversion must not wrap the positive estimate"
    );
    assert!(variation <= large);
    assert_eq!(estimator.min(), large);
    // This checks defensive Rust behavior, not C++ llround overflow equivalence.
}
