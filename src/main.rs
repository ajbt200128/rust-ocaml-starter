mod ocaml_bindings;
mod ocaml_symbols;

ocaml::import! {
    fn hello_world() -> String;
}

fn main() {
    let _ = ocaml::init();
    println!("Hello, world!");
}
