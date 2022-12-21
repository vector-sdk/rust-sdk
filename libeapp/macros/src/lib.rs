//! A macro that defines enclave application's entry point
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#[macro_use]
extern crate quote;
extern crate syn;
extern crate proc_macro;

use syn::{parse_macro_input, Error, ItemFn, ReturnType, Type, Visibility};
use syn::spanned::Spanned;

use proc_macro::TokenStream;

/// An attribute macro that is used to denote enclave application's entry point.
/// This macro should be used exactly once in the program.
///
/// The function will be the first application specific function called when an
/// enclave application starts. Enclave environment specific initializations may
/// be performed before calling the entry point function. Returning from the
/// entry point function will terminate the enclave as if 'eapp_return' would
/// have been called.
///
/// The entry point function must have the following signature:
///
///    pub fn() -> u64
///
/// The entry point function should take no parameters and return a 'u64' value.
/// This value is returned to the thread that started the enclave at the host
/// application exactly as if 'eapp_return' would have been called instead.
///

#[proc_macro_attribute]
pub fn eapp_entry(_args: TokenStream, input: TokenStream) -> TokenStream {

    // See: https://docs.rs/syn/latest/syn
    let func : syn::ItemFn = parse_macro_input!(input as ItemFn);

    // Only non-doc attributes are allowed currently:
    for attr in &func.attrs {
        if attr.path.leading_colon == None
            || attr.path.segments.len() == 1
        {
            if let Some(path) = attr.path.segments.first() {
                if path.ident == "doc" {
                    continue;
                }
            }
        }

        return Error::new(func.sig.span(),
                          "`#[eapp_entry]` function must have signature \
                           `pub fn() -> u64` and no other attributes")
             .to_compile_error().into();
    }

    // Signature check: pub fn () -> u64;
    if match func.vis {
        Visibility::Public(_) => false,
        _ => true
    }
    || func.sig.abi.is_some()
        || func.sig.asyncness.is_some()
        || func.sig.constness.is_some()
        || func.sig.unsafety.is_some()
        || func.sig.variadic.is_some()
        || func.sig.generics.params.len() > 0
        || func.sig.inputs.len() > 0
        || match func.sig.output {
            ReturnType::Default => true,
            ReturnType::Type(_, ref t) => match **t {
                Type::Path(ref tp) => {
                    !(tp.path.segments.len() == 1
                      && tp.path.segments.first().unwrap().ident.to_string() == "u64")
                },
                _ => true
            }
        } {
            return Error::new(func.sig.span(),
                              "`#[eapp_entry]` function must have signature `pub fn() -> u64`")
                .to_compile_error().into();
        }

    // Re-name the function and enforce (checked) signature:
    let attrs = func.attrs; // Add comments back to preserve documentation
    let ident = func.sig.ident;
    let stmts = func.block.stmts;

    let expanded = quote!{
        #(#attrs)*
        #[export_name = "_eapp_entry"]
        pub fn #ident() -> u64 {
            #(#stmts)*
        }
    };

    // Output tokens to the compiler:
    TokenStream::from(expanded)
}
