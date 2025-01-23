use alloc::vec;
use core::marker::PhantomData;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

#[cfg(test)]
use crate::column_pool::ConfigPhase;
use crate::{
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    AssignedCell, Fr,
};

/// Equation `Σ a_i * x_i = c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinearEquationGate<const N: usize, Config>
where
    Config: LinearEquationGateConfig<N>,
{
    variables: [Column<Advice>; N], // `x_i`
    selector: Selector,
    _marker: PhantomData<Config>,
}

pub trait LinearEquationGateConfig<const N: usize> {
    fn coefficients() -> [Fr; N]; // `a_i`
    fn constant_term() -> Fr; // `c`
    fn gate_name() -> &'static str;
}

#[derive(Clone, Debug)]
#[embeddable(
    receiver = "LinearEquationGateInput<Fr, N>",
    impl_generics = "<const N: usize>",
    embedded = "LinearEquationGateInput<AssignedCell, N>"
)]
pub struct LinearEquationGateInput<T, const N: usize> {
    pub variables: [T; N],
}

impl<const N: usize> Default for LinearEquationGateInput<Fr, N> {
    fn default() -> Self {
        Self {
            variables: [Fr::default(); N],
        }
    }
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;

impl<const N: usize, Config: LinearEquationGateConfig<N>> Gate for LinearEquationGate<N, Config> {
    type Input = LinearEquationGateInput<AssignedCell, N>;
    type Advices = [Column<Advice>; N];

    fn create_gate(cs: &mut ConstraintSystem<Fr>, variables: Self::Advices) -> Self {
        ensure_unique_columns(&variables);

        let coefficients = Config::coefficients();
        let constant_term = Config::constant_term();
        let selector = cs.selector();

        cs.create_gate(Config::gate_name(), |vc| {
            let selector = vc.query_selector(selector);

            let mut sum = -Expression::Constant(constant_term);
            for i in 0..N {
                let variable = vc.query_advice(variables[i], Rotation(ADVICE_OFFSET as i32));
                sum = sum + variable * Expression::Constant(coefficients[i]);
            }

            vec![selector * sum]
        });
        Self {
            variables,
            selector,
            _marker: PhantomData,
        }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input: Self::Input,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || Config::gate_name(),
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                for i in 0..N {
                    input.variables[i].copy_advice(
                        || alloc::format!("variable_{i}"),
                        &mut region,
                        self.variables[i],
                        ADVICE_OFFSET,
                    )?;
                }

                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut crate::column_pool::ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, N);
        pool.get_array()
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use halo2_proofs::{arithmetic::Field, plonk::ConstraintSystem};

    use super::{LinearEquationGateConfig, LinearEquationGateInput};
    use crate::{
        gates::{linear_equation::LinearEquationGate, test_utils::verify, Gate},
        Fr,
    };

    fn input<const N: usize>(variables: [impl Into<Fr>; N]) -> LinearEquationGateInput<Fr, N> {
        LinearEquationGateInput {
            variables: variables
                .into_iter()
                .map(|v| v.into())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }

    #[derive(Clone)]
    enum DecimalExampleConfig {}

    impl LinearEquationGateConfig<4> for DecimalExampleConfig {
        fn coefficients() -> [Fr; 4] {
            [Fr::from(100), Fr::from(10), Fr::from(1), Fr::from(1).neg()]
        }

        fn constant_term() -> Fr {
            Fr::ZERO
        }

        fn gate_name() -> &'static str {
            "Decimal system equation gate"
        }
    }

    #[test]
    fn accepts_valid_solution() {
        assert!(
            verify::<LinearEquationGate<4, DecimalExampleConfig>, _>(input([1, 2, 3, 123])).is_ok()
        );
    }

    #[test]
    fn accepts_alternative_valid_solution() {
        assert!(
            verify::<LinearEquationGate<4, DecimalExampleConfig>, _>(input([1, 0, 23, 123]))
                .is_ok()
        );
    }

    #[test]
    fn rejects_invalid_solution() {
        let errors =
            verify::<LinearEquationGate<4, DecimalExampleConfig>, _>(input([1, 2, 4, 123]))
                .expect_err("Verification should fail");
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .contains("Constraint 0 in gate 0 ('Decimal system equation gate') is not satisfied"));
    }

    #[test]
    #[should_panic = "Advice columns must be unique"]
    fn gate_creation_with_not_distinct_columns_fails() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let column_1 = cs.advice_column();
        let column_2 = cs.advice_column();
        let column_3 = cs.advice_column();

        LinearEquationGate::<4, DecimalExampleConfig>::create_gate(
            &mut cs,
            [column_1, column_2, column_3, column_3],
        );
    }

    #[derive(Clone)]
    enum ConstantExampleConfig<const C: u64> {}

    impl<const C: u64> LinearEquationGateConfig<1> for ConstantExampleConfig<C> {
        fn coefficients() -> [Fr; 1] {
            [Fr::from(1)]
        }

        fn constant_term() -> Fr {
            Fr::from(C)
        }

        fn gate_name() -> &'static str {
            "Constant equation gate"
        }
    }

    #[test]
    fn passes_if_constant_term_matched() {
        assert!(verify::<LinearEquationGate<1, ConstantExampleConfig<42>>, _>(input([42])).is_ok());
    }

    #[test]
    fn fails_if_constant_term_unmatched() {
        let errors = verify::<LinearEquationGate<1, ConstantExampleConfig<42>>, _>(input([43]))
            .expect_err("Verification should fail");
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .contains("Constraint 0 in gate 0 ('Constant equation gate') is not satisfied"));
    }
}
