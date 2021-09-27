use std::prelude::v1::*;
use erased_serde::ser::*;
use serde_json;

fn test_json<T>(t: T)
where
    T: serde::Serialize,
{
    let expected = serde_json::to_vec(&t).unwrap();

    // test borrowed trait object
    {
        let obj: &dyn Serialize = &t;

        let mut buf = Vec::new();

        {
            let mut ser = serde_json::Serializer::new(&mut buf);
            let ser: &mut dyn Serializer = &mut Serializer::erase(&mut ser);

            obj.erased_serialize(ser).unwrap();
        }

        assert_eq!(buf, expected);
    }

    // test boxed trait object
    {
        let obj: Box<dyn Serialize> = Box::new(t);

        let mut buf = Vec::new();

        {
            let mut ser = serde_json::Serializer::new(&mut buf);
            let mut ser: Box<dyn Serializer> = Box::new(Serializer::erase(&mut ser));

            obj.erased_serialize(&mut ser).unwrap();
        }

        assert_eq!(buf, expected);
    }
}

//#[test]
pub fn test_vec() {
    test_json(vec!["a", "b"]);
}

//#[test]
pub fn test_struct() {
    #[derive(Serialize)]
    struct S {
        f: usize,
    }

    test_json(S { f: 256 });
}

//#[test]
pub fn test_enum() {
    #[derive(Serialize)]
    enum E {
        Unit,
        Newtype(bool),
        Tuple(bool, bool),
        Struct { t: bool, f: bool },
    }

    test_json(E::Unit);
    test_json(E::Newtype(true));
    test_json(E::Tuple(true, false));
    test_json(E::Struct { t: true, f: false });
}

//#[test]
pub fn assert_serialize() {
    fn assert<T: serde::Serialize>() {}

    assert::<&dyn Serialize>();
    assert::<&(dyn Serialize + Send)>();
    assert::<&(dyn Serialize + Sync)>();
    assert::<&(dyn Serialize + Send + Sync)>();
    assert::<&(dyn Serialize + Sync + Send)>();
    assert::<Vec<&dyn Serialize>>();
    assert::<Vec<&(dyn Serialize + Send)>>();

    assert::<Box<dyn Serialize>>();
    assert::<Box<dyn Serialize + Send>>();
    assert::<Box<dyn Serialize + Sync>>();
    assert::<Box<dyn Serialize + Send + Sync>>();
    assert::<Box<dyn Serialize + Sync + Send>>();
    assert::<Vec<Box<dyn Serialize>>>();
    assert::<Vec<Box<dyn Serialize + Send>>>();
}

//#[test]
pub fn assert_serializer() {
    fn assert<T: serde::Serializer>() {}

    assert::<&mut dyn Serializer>();
    assert::<&mut (dyn Serializer + Send)>();
    assert::<&mut (dyn Serializer + Sync)>();
    assert::<&mut (dyn Serializer + Send + Sync)>();
    assert::<&mut (dyn Serializer + Sync + Send)>();
}
