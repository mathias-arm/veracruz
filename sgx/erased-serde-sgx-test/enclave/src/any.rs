use erased_serde::any::*;

pub fn test_fingerprint() {
    assert_eq!(Fingerprint::of::<usize>(), Fingerprint::of::<usize>());
    assert_eq!(Fingerprint::of::<&str>(), Fingerprint::of::<&'static str>());

    assert_ne!(Fingerprint::of::<usize>(), Fingerprint::of::<isize>());
    assert_ne!(Fingerprint::of::<usize>(), Fingerprint::of::<&usize>());
    assert_ne!(Fingerprint::of::<&usize>(), Fingerprint::of::<&&usize>());
    assert_ne!(Fingerprint::of::<&usize>(), Fingerprint::of::<&mut usize>());

    struct A;
    struct B;
    assert_ne!(Fingerprint::of::<A>(), Fingerprint::of::<B>());
}
