use darling::{ast::NestedMeta, FromMeta};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::ItemStruct;

type SynResult<T> = Result<T, syn::Error>;

#[derive(Debug, FromMeta)]
struct Attributes {
    field_type: Option<syn::Path>,
    receiver: syn::Type,
    impl_generics: String,
    embedded: syn::Type,
}

/// Auxiliary function to enter ?-based error propagation.
pub fn embeddable(attr: TokenStream2, item: TokenStream2) -> SynResult<TokenStream2> {
    let item_struct = syn::parse2::<ItemStruct>(item)?;
    let backed_up_struct = item_struct.clone();

    let Attributes {
        field_type,
        receiver,
        impl_generics,
        embedded,
    } = Attributes::from_list(&NestedMeta::parse_meta_list(attr)?)?;
    let field_type = field_type.unwrap_or_else(|| syn::parse_quote!(F));
    let impl_generics = syn::parse_str::<syn::Generics>(&impl_generics)?;

    let struct_name = item_struct.ident;

    let field_embedding = item_struct.fields.iter().map(|field| {
        let field_name = &field.ident.clone().expect("Only named fields are supported");
        quote! {
            #field_name: self.#field_name.embed(&mut layouter, advice_pool, stringify!(#field_name))?
        }
    });

    Ok(quote! {
        #backed_up_struct

        impl #impl_generics Embed for #receiver {
            type Embedded = #embedded;

            fn embed(
                &self,
                layouter: &mut impl halo2_proofs::circuit::Layouter< #field_type >,
                advice_pool: &crate::column_pool::ColumnPool<halo2_proofs::plonk::Advice, crate::column_pool::SynthesisPhase>,
                annotation: impl Into<alloc::string::String>,
            ) -> Result<Self::Embedded, halo2_proofs::plonk::Error> {
                let mut layouter = layouter.namespace(|| annotation);
                Ok(#struct_name {
                    #(#field_embedding),*
                })
            }
        }
    })
}
