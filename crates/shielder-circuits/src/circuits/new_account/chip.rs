use halo2_proofs::{arithmetic::Field, plonk::ErrorFront};

use crate::{
    chips::{
        asymmetric_encryption::ElGamalEncryptionChip,
        is_point_on_curve_affine::{IsPointOnCurveAffineChip, IsPointOnCurveAffineChipInput},
        note::{Note, NoteChip},
        sym_key::SymKeyChip,
    },
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    curve_arithmetic::{self, GrumpkinPointAffine},
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance::{self, *},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note: NoteChip,
    pub is_point_on_curve: IsPointOnCurveAffineChip,
}

impl NewAccountChip {
    pub fn check_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
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
    ) -> Result<(), ErrorFront> {
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
    ) -> Result<(), ErrorFront> {
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
    ) -> Result<(), ErrorFront> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        self.constrain_symmetric_key(synthesizer, sym_key.clone())?;

        let revoker_pkey = knowledge.anonymity_revoker_public_key.clone();
        let sym_key_encryption =
            ElGamalEncryptionChip {}.encrypt(synthesizer, revoker_pkey.clone(), sym_key)?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [
                (revoker_pkey.x, AnonymityRevokerPublicKeyX),
                (revoker_pkey.y, AnonymityRevokerPublicKeyY),
                (sym_key_encryption, SymKeyEncryption),
            ],
        )
    }
}
