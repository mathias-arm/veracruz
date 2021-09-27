use std::prelude::v1::*;
use serde;
use erased_serde::Serialize;

fn assert_serialize<T: ?Sized + serde::Serialize>() {}

//#[test]
pub fn test_plain() {
    trait Trait: Serialize {}

    serialize_trait_object!(Trait);
    assert_serialize::<dyn Trait>();
    assert_serialize::<dyn Trait + Send>();
}

//#[test]
pub fn test_type_parameter() {
    trait Trait<T>: Serialize {}

    serialize_trait_object!(<T> Trait<T>);
    assert_serialize::<dyn Trait<u32>>();
    assert_serialize::<dyn Trait<u32> + Send>();
}

//#[test]
pub fn test_generic_bound() {
    trait Trait<T: PartialEq<T>, U>: Serialize {}

    serialize_trait_object!(<T: PartialEq<T>, U> Trait<T, U>);
    assert_serialize::<dyn Trait<u32, ()>>();
    assert_serialize::<dyn Trait<u32, ()> + Send>();
}

//#[test]
pub fn test_where_clause() {
    trait Trait<T>: Serialize
    where
        T: Clone,
    {
    }

    serialize_trait_object!(<T> Trait<T> where T: Clone);
    assert_serialize::<dyn Trait<u32>>();
    assert_serialize::<dyn Trait<u32> + Send>();
}
