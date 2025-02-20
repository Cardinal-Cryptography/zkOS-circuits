use alloc::{vec, vec::Vec};

use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::Error};

use crate::{
    chips::{
        asymmetric_encryption::{
            ElGamalEncryptionChip, ElGamalEncryptionChipOutput, ElGamalEncryptionInput,
        },
        is_point_on_curve_affine::{IsPointOnCurveAffineChip, IsPointOnCurveAffineChipInput},
        note::{Note, NoteChip},
        sym_key::SymKeyChip,
        to_affine::{ToAffineChip, ToAffineChipInput, ToAffineChipOutput},
        to_projective::{ToProjectiveChip, ToProjectiveChipInput, ToProjectiveChipOutput},
    },
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    curve_arithmetic::{self, GrumpkinPointAffine},
    embed::Embed,
    field_element_to_le_bits,
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance::{self, *},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell, GrumpkinPoint, Value,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note: NoteChip,
    pub is_point_on_curve: IsPointOnCurveAffineChip,
    pub el_gamal_encryption: ElGamalEncryptionChip,
    pub to_projective: ToProjectiveChip,
    pub to_affine: ToAffineChip,
}

impl NewAccountChip {
    pub fn check_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let note = self.note.note_hash(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier.clone(),
                trapdoor: knowledge.trapdoor.clone(),
                account_balance: knowledge.initial_deposit.clone(),
                token_address: knowledge.token_address.clone(),
            },
        )?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [
                (note, HashedNote),
                (knowledge.initial_deposit.clone(), InitialDeposit),
            ],
        )
    }

    pub fn constrain_hashed_id(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let h_id = hash(synthesizer, self.poseidon.clone(), [knowledge.id.clone()])?;
        self.public_inputs
            .constrain_cells(synthesizer, [(h_id, HashedId)])
    }

    /// check whether symmetric key is such that it forms a quadratic reside on the Grumpkin curve
    /// y^2 = key^3 - 17
    fn constrain_symmetric_key(
        &self,
        synthesizer: &mut impl Synthesizer,
        key: AssignedCell,
    ) -> Result<(), Error> {
        let y_squared_value =
            curve_arithmetic::quadratic_residue_given_x_affine(key.value().copied());
        let y_value =
            y_squared_value.map(|v| v.sqrt().expect("element does not have a square root"));
        let y = y_value.embed(synthesizer, "y")?;

        self.is_point_on_curve.is_point_on_curve_affine(
            synthesizer,
            &IsPointOnCurveAffineChipInput {
                point: GrumpkinPointAffine::new(key, y),
            },
        )
    }

    pub fn constrain_sym_key_encryption(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        self.constrain_symmetric_key(synthesizer, sym_key.clone())?;

        let mut bits_vec: Vec<Value> = vec![];

        knowledge
            .trapdoor
            .value()
            .cloned()
            .map(field_element_to_le_bits)
            .map(|array| {
                bits_vec = array.into_iter().map(Value::known).collect();
            });

        let revoker_pkey = knowledge.anonymity_revoker_public_key.clone();

        let ToProjectiveChipOutput {
            point_projective: revoker_pkey_projective,
        } = self.to_projective.to_projective(
            synthesizer,
            &ToProjectiveChipInput {
                point_affine: revoker_pkey.clone(),
            },
        )?;

        let bits_values: [Value; 254] = bits_vec.try_into().expect("value is not 254 bits long");
        let bits = bits_values.embed(synthesizer, "trapdor_le_bits")?;

        let y_value = curve_arithmetic::quadratic_residue_given_x_affine(sym_key.value().copied())
            .map(|elem| elem.sqrt().expect("element has a square root"));
        let y = y_value.embed(synthesizer, "y")?;
        let z = synthesizer.assign_constant("ONE", Fr::ONE)?;

        let ElGamalEncryptionChipOutput {
            ciphertext1: c1_projective,
            ciphertext2: c2_projective,
        } = self.el_gamal_encryption.encrypt(
            synthesizer,
            &ElGamalEncryptionInput {
                message: GrumpkinPoint::new(sym_key, y, z),
                public_key: revoker_pkey_projective,
                trapdoor_le_bits: bits,
            },
        )?;

        let ToAffineChipOutput {
            point_affine: c1_affine,
        } = self.to_affine.to_affine(
            synthesizer,
            &ToAffineChipInput {
                point_projective: c1_projective,
            },
        )?;

        let ToAffineChipOutput {
            point_affine: c2_affine,
        } = self.to_affine.to_affine(
            synthesizer,
            &ToAffineChipInput {
                point_projective: c2_projective,
            },
        )?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [
                (revoker_pkey.x, AnonymityRevokerPublicKeyX),
                (revoker_pkey.y, AnonymityRevokerPublicKeyY),
                (c1_affine.x, SymKeyEncryptionCiphertext1X),
                (c1_affine.y, SymKeyEncryptionCiphertext1Y),
                (c2_affine.x, SymKeyEncryptionCiphertext2X),
                (c2_affine.y, SymKeyEncryptionCiphertext2Y),
            ],
        )
    }
}
