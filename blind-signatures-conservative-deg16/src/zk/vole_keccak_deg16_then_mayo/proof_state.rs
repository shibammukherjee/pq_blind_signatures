use crate::zk::vole_keccak_deg16_then_mayo::parameters::VOLEKeccakDeg16ThenMAYOParameters;

/// Defines the intermediate proof state, that is described by the output of
/// `prove`. Primarily used to initialize the proof state before it is converted
/// to the final proof.
#[derive(Clone)]
pub struct VOLEKeccakDeg16ThenMAYOProofState {
    pub proof: Vec<u8>,
    pub random_seed: Vec<u8>,
}

/// Just a capture for the [`VOLEKeccakDeg16ThenMAYOProof`] type.
pub struct VOLEKeccakDeg16ThenMAYOProof {
    pub proof: Vec<u8>,
}

impl From<VOLEKeccakDeg16ThenMAYOProofState> for VOLEKeccakDeg16ThenMAYOProof {
    /// Extracts the proof from a [`VOLEKeccakDeg16ThenMAYOProofState`] after `prove` was called.
    fn from(value: VOLEKeccakDeg16ThenMAYOProofState) -> Self {
        VOLEKeccakDeg16ThenMAYOProof { proof: value.proof }
    }
}

impl VOLEKeccakDeg16ThenMAYOProofState {
    /// Initiates a state and allocates sufficient space in memory based on the provided
    /// [`VOLEKeccakDeg16ThenMAYOParameters`].
    pub fn init(p: &VOLEKeccakDeg16ThenMAYOParameters) -> Self {
        let proof = vec![0u8; p.proof_size];
        let random_seed = vec![0u8; p.random_seed_size];

        VOLEKeccakDeg16ThenMAYOProofState { proof, random_seed }
    }
}
