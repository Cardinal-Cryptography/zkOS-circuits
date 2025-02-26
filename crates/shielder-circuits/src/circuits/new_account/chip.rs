use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::Error};

use crate::{
    chips::{
        el_gamal::{ElGamalEncryptionChip, ElGamalEncryptionChipOutput, ElGamalEncryptionInput},
        note::{Note, NoteChip},
        sym_key::SymKeyChip,
        to_affine::ToAffineChip,
        to_projective::ToProjectiveChip,
    },
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    curve_arithmetic::{self, GrumpkinPointAffine},
    embed::Embed,
    gates::{is_point_on_curve_affine::IsPointOnCurveAffineGate, Gate},
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance::{self, *},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell, GrumpkinPoint,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note: NoteChip,
    pub is_point_on_curve: IsPointOnCurveAffineGate,
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

        self.is_point_on_curve
            .apply_in_new_region(synthesizer, GrumpkinPointAffine::new(key, y))
    }

    pub fn constrain_sym_key_encryption(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        self.constrain_symmetric_key(synthesizer, sym_key.clone())?;

        let revoker_pkey = knowledge.anonymity_revoker_public_key.clone();

        let revoker_pkey_projective = self
            .to_projective
            .to_projective(synthesizer, &revoker_pkey)?;

        let y_value = curve_arithmetic::quadratic_residue_given_x_affine(sym_key.value().copied())
            .map(|elem| elem.sqrt().expect("element has a square root"));
        let y = y_value.embed(synthesizer, "y")?;

        self.is_point_on_curve.apply_in_new_region(
            synthesizer,
            GrumpkinPointAffine::new(sym_key.clone(), y.clone()),
        )?;

        let z = synthesizer.assign_constant("ONE", Fr::ONE)?;

        let ElGamalEncryptionChipOutput {
            ciphertext1: c1_projective,
            ciphertext2: c2_projective,
        } = self.el_gamal_encryption.encrypt(
            synthesizer,
            &ElGamalEncryptionInput {
                message: GrumpkinPoint::new(sym_key, y, z),
                public_key: revoker_pkey_projective,
                salt_le_bits: knowledge.encryption_salt.clone(),
            },
        )?;

        let c1_affine = self.to_affine.to_affine(synthesizer, &c1_projective)?;
        let c2_affine = self.to_affine.to_affine(synthesizer, &c2_projective)?;

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
