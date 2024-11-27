use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{gates::Gate, AssignedCell};

/// Represents the relation: `(needle - haystack_1) · … · (needle - haystack_N) = 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MembershipGate<const N: usize> {
    needle_advice: Column<Advice>,
    haystack_advice: [Column<Advice>; N],
    selector: Selector,
}

#[derive(Clone, Debug)]
pub struct MembershipGateValues<F: Field, const N: usize> {
    pub needle: AssignedCell<F>,
    pub haystack: [AssignedCell<F>; N],
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Membership gate";

impl<F: Field, const N: usize> Gate<F> for MembershipGate<N> {
    type Values = MembershipGateValues<F, N>;
    type Advices = (Column<Advice>, [Column<Advice>; N]);

    fn create_gate(
        cs: &mut ConstraintSystem<F>,
        (needle_advice, haystack_advice): Self::Advices,
    ) -> Self {
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let needle = vc.query_advice(needle_advice, Rotation(ADVICE_OFFSET as i32));
            let selector = vc.query_selector(selector);

            [haystack_advice.iter().fold(selector, |product, &hay| {
                let element = vc.query_advice(hay, Rotation(ADVICE_OFFSET as i32));
                product * (needle.clone() - element)
            })]
        });

        Self {
            needle_advice,
            haystack_advice,
            selector,
        }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        mut input: Self::Values,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                input.needle.copy_advice(
                    || "needle",
                    &mut region,
                    self.needle_advice,
                    ADVICE_OFFSET,
                )?;

                for (i, hay) in input.haystack.iter_mut().enumerate() {
                    hay.copy_advice(
                        || alloc::format!("haystack_{i}"),
                        &mut region,
                        self.haystack_advice[i],
                        ADVICE_OFFSET,
                    )?;
                }

                Ok(())
            },
        )
    }
}
