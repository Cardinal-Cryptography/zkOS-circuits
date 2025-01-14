use crate::F;

pub const NOTE_VERSION: NoteVersion = NoteVersion(0);

#[derive(Copy, Clone, Debug)]
pub struct NoteVersion(u8);

impl NoteVersion {
    pub fn new(note_version: u8) -> Self {
        Self(note_version)
    }
    pub fn as_field(&self) -> F {
        F::from(self.0 as u64)
    }
}
