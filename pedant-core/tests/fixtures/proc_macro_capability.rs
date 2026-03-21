#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_derive(MyDerive)]
fn my_derive(input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
fn my_attr(attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
