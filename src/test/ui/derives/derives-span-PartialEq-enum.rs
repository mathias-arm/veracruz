// This file was auto-generated using 'src/etc/generate-deriving-span-tests.py'


struct Error;

#[derive(PartialEq)]
enum Enum {
   A(
     Error //~ ERROR
//~^ ERROR
     )
}

fn main() {}
