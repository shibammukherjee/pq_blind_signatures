use crate::zk::vole_keccak_then_mayo::parameters::VOLEKeccakThenMAYOParameters;

/// Defines the intermediate proof state, that is described by the output of
/// `prove`. Primarily used to initialize the proof state before it is converted
/// to the final proof.
#[derive(Clone)]
pub struct VOLEKeccakThenMAYOProofState {
    pub proof: Vec<u8>,
    pub random_seed: Vec<u8>,
}

/// Just a capture for the [`VOLEKeccakThenMAYOProof`] type.
pub struct VOLEKeccakThenMAYOProof {
    pub proof: Vec<u8>,
}

impl From<VOLEKeccakThenMAYOProofState> for VOLEKeccakThenMAYOProof {
    /// Extracts the proof from a [`VOLEKeccakThenMAYOProof`] after `prove` was called.
    fn from(value: VOLEKeccakThenMAYOProofState) -> Self {
        VOLEKeccakThenMAYOProof { proof: value.proof }
    }
}

impl VOLEKeccakThenMAYOProofState {
    /// Initiates a state and allocates sufficient space in memory based on the provided
    /// [`VOLEKeccakThenMAYOParameters`].
    pub fn init(p: &VOLEKeccakThenMAYOParameters) -> Self {
        let proof = vec![0u8; p.proof_size];
        let random_seed = vec![0u8; p.random_seed_size];

        VOLEKeccakThenMAYOProofState { proof, random_seed }
    }
}
