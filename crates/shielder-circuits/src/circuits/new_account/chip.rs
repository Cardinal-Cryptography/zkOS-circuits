use halo2_proofs::{arithmetic::CurveExt, halo2curves::grumpkin::G1, plonk::ErrorFront};

use crate::{
    chips::{
        asymmetric_encryption::ElGamalEncryptionChip,
        is_quadratic_residue::IsQuadraticResidueChip,
        note::{Note, NoteChip},
        sym_key::SymKeyChip,
    },
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    curve_arithmetic::GrumpkinPointAffine,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance::{self, *},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell, Value,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note: NoteChip,
    pub is_quadratic_residue: IsQuadraticResidueChip,
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
    fn is_key_quadratic_residue(
        &self,
        synthesizer: &mut impl Synthesizer,
        key: AssignedCell,
    ) -> Result<(), ErrorFront> {
        self.is_quadratic_residue.check_coordinate(synthesizer, key)
    }

    pub fn constrain_sym_key_encryption(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        self.is_key_quadratic_residue(synthesizer, sym_key.clone())?;

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
