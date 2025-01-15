use proc_macro::TokenStream;

mod embed;

/// Derive the `Embed` trait for a struct.
///
/// # Requirements
///
/// 1. All the fields of the struct already implement `Embed`.
/// 2. Only structs with named fields are supported
/// 3. `halo2_proofs` must be in scope.
/// 4. Can be used only in the `shielder_circuits` crate.
///
/// # Attributes
///
/// - `field_type`: The type of the field that will be used in the `Embed` trait implementation.
///    If not provided, literal `F` is used.
/// - `receiver`: The type of the struct that will implement the `Embed` trait.
/// - `impl_generics`: Generics that will be used in the `Embed` trait implementation.
/// - `embedded`: The type that the struct will be embedded into.
///
/// # Example
///
/// ```no_run
/// use crate::embeddable;
///
/// #[embeddable(
///     receiver = "IntermediateValues<Value<F>>",
///     impl_generics = "",
///     embedded = "IntermediateValues<crate::AssignedCell>"
/// )]
/// pub struct IntermediateValues<F> {
///     /// Account balance after the deposit is made.
///     pub account_new_balance: F,
/// }
/// ```
///
/// This will generate the following code:
///
/// ```rust, no_run
/// impl Embed for IntermediateValues<Value<F>> {
///     type Embedded = IntermediateValues<crate::AssignedCell>;
///     fn embed(
///         &self,
///         layouter: &mut impl halo2_proofs::circuit::Layouter<F>,
///         advice_pool: &crate::column_pool::ColumnPool<halo2_proofs::plonk::Advice>,
///         annotation: impl Into<alloc::string::String>,
///     ) -> Result<Self::Embedded, halo2_proofs::plonk::Error> {
///         let mut layouter = layouter.namespace(|| annotation);
///         Ok(IntermediateValues {
///             account_new_balance: self
///                 .account_new_balance
///                 .embed(&mut layouter, advice_pool, "account_new_balance")?,
///         })
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn embeddable(attr: TokenStream, item: TokenStream) -> TokenStream {
    match embed::embeddable(attr.into(), item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
