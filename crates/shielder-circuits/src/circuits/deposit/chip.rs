use halo2_proofs::plonk::Error;
use DepositInstance::DepositValue;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        mac::{MacChip, MacInput},
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
        sym_key::SymKeyChip,
    },
    circuits::{
        deposit::knowledge::DepositProverKnowledge,
        merkle::{MerkleChip, MerkleProverKnowledge},
    },
    deposit::DepositInstance::{self, HashedNewNote, HashedOldNullifier, *},
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct DepositChip {
    pub public_inputs: InstanceWrapper<DepositInstance>,
    pub poseidon: PoseidonChip,
    pub range_check: RangeCheckChip,
    pub sum_chip: SumChip,
    pub merkle: MerkleChip,
    pub note: NoteChip,
}

impl DepositChip {
    pub fn check_old_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let old_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_old.clone(),
                trapdoor: knowledge.trapdoor_old.clone(),
                account_balance: knowledge.account_old_balance.clone(),
            },
        )?;

        self.merkle.synthesize(
            synthesizer,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
        )
    }

    pub fn check_old_nullifier(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let hashed_old_nullifier = hash(
            synthesizer,
            self.poseidon.clone(),
            [knowledge.nullifier_old.clone()],
        )?;

        self.public_inputs
            .constrain_cells(synthesizer, [(hashed_old_nullifier, HashedOldNullifier)])
    }

    pub fn check_id_hiding(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let id_hiding = IdHidingChip::new(self.poseidon.clone(), self.range_check.clone())
            .id_hiding(synthesizer, knowledge.id.clone(), knowledge.nonce.clone())?;
        self.public_inputs
            .constrain_cells(synthesizer, [(id_hiding, IdHiding)])
    }

    pub fn check_new_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        self.public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.deposit_value.clone(), DepositValue)],
        )?;

        // TODO: move to another chip or `IntermediateValues`.
        let account_balance_new = synthesizer.assign_value(
            "balance new",
            knowledge.account_old_balance.value() + knowledge.deposit_value.value(),
        )?;
        self.sum_chip.constrain_sum(
            synthesizer,
            knowledge.account_old_balance.clone(),
            knowledge.deposit_value.clone(),
            account_balance_new.clone(),
        )?;

        let new_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                account_balance: account_balance_new,
            },
        )?;

        self.public_inputs
            .constrain_cells(synthesizer, [(new_note, HashedNewNote)])
    }

    pub fn check_mac(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        MacChip::new(self.poseidon.clone()).mac(
            synthesizer,
            &MacInput {
                key: sym_key,
                salt: knowledge.mac_salt.clone(),
            },
        )?;
        Ok(())
    }
}
