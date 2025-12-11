use crate::zk::{
    ZKType,
    vole_rain_then_mayo::{
        parameters::VOLERainThenMAYOParameters,
        proof_state::{VOLERainThenMAYOProof, VOLERainThenMAYOProofState},
    },
};

pub mod parameters;
pub mod proof_state;

pub const VOLERAINHASH_RC_SIZE: usize = 64 * 7;
pub const VOLERAINHASH_MAT_SIZE: usize = 64 * 512 * 7;

pub static ROUND_CONST: [u8; VOLERAINHASH_RC_SIZE] = [u8::MAX; VOLERAINHASH_RC_SIZE];
pub static MAT: [u8; VOLERAINHASH_MAT_SIZE] = [u8::MAX; VOLERAINHASH_MAT_SIZE];

/// This struct acts as the object callable to utilize the functionalities of [`VOLERainThenMAYO`].
/// With it, you can generate proofs (prove) and validate proofs using
/// different parametersets.
/// It is used within the optimized blind signature [`BlindSignatureConservativeRain`](crate::blind_sig_conservative_rain::BlindSignatureConservativeRain).
pub struct VOLERainThenMAYO {
    pub vole_rain_then_mayo_params: VOLERainThenMAYOParameters,
}

impl VOLERainThenMAYO {
    /// Given one of the parameter options (defined by [`ZKType`]), fix all functions and
    /// parameters for that specific parameter set.
    pub fn setup(params: ZKType) -> Self {
        VOLERainThenMAYO {
            vole_rain_then_mayo_params: VOLERainThenMAYOParameters::setup(params),
        }
    }

    /// Computes a [`VOLERainThenMAYOProof`] that contains a proof for:
    /// - the commitment (SHAKE256 with degree 16),
    /// - the target computation (SHAKE256 with degree 16) and
    /// - MAYO.
    pub fn prove(
        &self,
        epk: &mut [u8],
        msg: &mut [u8],
        signature: &mut [u8],
        rand: &mut [u8],
        salt: &mut [u8],
        additional_r: &mut [u8],
    ) -> VOLERainThenMAYOProof {
        let mut state = VOLERainThenMAYOProofState::init(&self.vole_rain_then_mayo_params);

        let msg_hash = msg;

        assert!(unsafe {
            (self.vole_rain_then_mayo_params.prove_fn)(
                state.proof.as_mut_ptr(),
                state.random_seed.as_mut_ptr(),
                state.random_seed.len(),
                epk.as_mut_ptr(),
                msg_hash.as_mut_ptr(),
                ROUND_CONST.clone().as_mut_ptr(),
                MAT.clone().as_mut_ptr(),
                signature.as_mut_ptr(),
                rand.as_mut_ptr(),
                salt.as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        });

        VOLERainThenMAYOProof::from(state)
    }

    /// Verifies the zk proof for a message, the proof and public keys.
    pub fn verify(
        &self,
        proof: &mut VOLERainThenMAYOProof,
        epk: &mut [u8],
        msg_hash: &mut [u8],
        additional_r: &mut [u8],
    ) -> bool {
        unsafe {
            (self.vole_rain_then_mayo_params.verify_fn)(
                proof.proof.as_mut_ptr(),
                proof.proof.len(),
                epk.as_mut_ptr(),
                msg_hash.as_mut_ptr(),
                ROUND_CONST.clone().as_mut_ptr(),
                MAT.clone().as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        }
    }
}
