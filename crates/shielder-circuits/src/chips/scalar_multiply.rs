use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr, plonk::Error};

use super::{point_double::PointDoubleChip, points_add::PointsAddChip};
use crate::{
    chips::{point_double::PointDoubleChipInput, points_add::PointsAddChipInput},
    curve_arithmetic::GrumpkinPoint,
    embed::Embed,
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct ScalarMultiplyChipInput<T> {
    pub p: GrumpkinPoint<T>,
    pub scalar_bits: [T; 254],
}

impl<T: Default + Copy> Default for ScalarMultiplyChipInput<T> {
    fn default() -> Self {
        Self {
            p: GrumpkinPoint::default(),
            scalar_bits: [T::default(); 254],
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ScalarMultiplyChipOutput<T> {
    pub s: GrumpkinPoint<T>,
}

// /// Chip that computes the result of adding a point P on the grumpkin to itself n times.
// ///
// /// nP = S
// #[derive(Clone, Debug)]
// pub struct ScalarMultiplyChip {
//     pub points_add: PointsAddChip,
//     pub point_double: PointDoubleChip,
// }

// impl ScalarMultiplyChip {
//     pub fn new(points_add: PointsAddChip, point_double: PointDoubleChip) -> Self {
//         Self {
//             point_double,
//             points_add,
//         }
//     }

//     pub fn scalar_multiply(
//         &self,
//         synthesizer: &mut impl Synthesizer,
//         input: &ScalarMultiplyChipInput<AssignedCell>,
//     ) -> Result<ScalarMultiplyChipOutput<AssignedCell>, Error> {
//         let ScalarMultiplyChipInput { scalar_bits, p } = input;

//         let r_value = GrumpkinPoint::new(
//             Value::known(Fr::zero()),
//             Value::known(Fr::one()),
//             Value::known(Fr::zero()),
//         );
//         let mut r = r_value.embed(synthesizer, "r")?;

//         let mut doubled = p.clone();

//         for bit in scalar_bits {
//             let mut is_one = false;
//             bit.value().map(|f| {
//                 is_one = Fr::one() == *f;
//             });

//             if is_one {
//                 let chip_input = PointsAddChipInput {
//                     p: r.clone(),
//                     q: doubled.clone(),
//                 };
//                 r = self.points_add.points_add(synthesizer, &chip_input)?.s;
//             }

//             let chip_input = PointDoubleChipInput { p: doubled.clone() };
//             doubled = self.point_double.point_double(synthesizer, &chip_input)?.s;
//         }

//         Ok(ScalarMultiplyChipOutput { s: r })
//     }
// }

#[cfg(test)]
mod tests {

    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{ScalarMultiplyChipInput, ScalarMultiplyChipOutput};
    use crate::{
        chips::{
            point_double::{PointDoubleChip, PointDoubleChipInput},
            points_add::{PointsAddChip, PointsAddChipInput},
        },
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        consts::GRUMPKIN_3B,
        curve_arithmetic::{self, field_element_to_bits, GrumpkinPoint},
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
        Value,
    };

    #[derive(Clone, Debug, Default)]
    struct ScalarMultiplyCircuit(ScalarMultiplyChipInput<Fr>);

    impl Circuit<Fr> for ScalarMultiplyCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            PointDoubleChip,
            PointsAddChip,
            Column<Instance>,
        );

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            // public input column
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // register chip
            let configs_builder = ConfigsBuilder::new(meta)
                .with_point_double_chip()
                .with_points_add_chip();
            let points_add = configs_builder.points_add_chip();
            let point_double = configs_builder.point_double_chip();

            (configs_builder.finish(), point_double, points_add, instance)
        }

        fn synthesize(
            &self,
            (column_pool, point_double, points_add, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            // println!("@synthesize");

            let ScalarMultiplyChipInput { p, scalar_bits } = self.0.clone();

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let r_value = GrumpkinPoint::new(
                Value::known(Fr::zero()),
                Value::known(Fr::one()),
                Value::known(Fr::zero()),
            );
            let mut r = r_value.embed(&mut synthesizer, "R")?;

            let scalar_bits = scalar_bits.embed(&mut synthesizer, "scalar_bits")?;

            let mut p = p.embed(&mut synthesizer, "P")?;

            // let res =
            //     curve_arithmetic::scalar_multiply(p, scalar_bits, *GRUMPKIN_3B, Fr::ZERO, Fr::ONE);

            for bit in scalar_bits {
                let mut is_one = false;
                bit.value().map(|f| {
                    is_one = Fr::one() == *f;
                });

                if is_one {
                    r = points_add
                        .points_add(&mut synthesizer, &PointsAddChipInput { p: r, q: p.clone() })?
                        .s;
                }

                p = point_double
                    .point_double(&mut synthesizer, &PointDoubleChipInput { p })?
                    .s;
            }

            // synthesizer.constrain_instance(s.x.cell(), instance, 0)?;
            // synthesizer.constrain_instance(s.y.cell(), instance, 1)?;
            // synthesizer.constrain_instance(s.z.cell(), instance, 2)?;

            // println!("@end: synthesize");

            Ok(())
        }
    }

    fn input(p: G1, scalar_bits: [Fr; 254]) -> ScalarMultiplyChipInput<Fr> {
        ScalarMultiplyChipInput {
            p: p.into(),
            scalar_bits: scalar_bits.into(),
        }
    }

    fn verify(
        input: ScalarMultiplyChipInput<Fr>,
        expected: ScalarMultiplyChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ScalarMultiplyCircuit(input);
        MockProver::run(
            10,
            &circuit,
            vec![vec![expected.s.x, expected.s.y, expected.s.z]],
        )
        .expect("Mock prover should run")
        .verify()
    }

    #[test]
    fn multiply_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());

        println!("P: {p:?}");

        let n = Fr::from_u128(3);
        let bits = field_element_to_bits(n);

        let expected = curve_arithmetic::scalar_multiply(
            p.into(),
            bits.clone(),
            *GRUMPKIN_3B,
            Fr::ZERO,
            Fr::ONE,
        );

        let input = input(p, bits);
        let output = ScalarMultiplyChipOutput { s: expected };

        assert!(verify(input, output).is_ok());
    }
}
