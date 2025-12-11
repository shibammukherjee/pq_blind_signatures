use super::BlindSignatureConservative;
use crate::zk::ZKType;
use crate::zk::vole_keccak_then_mayo::VOLEKeccakThenMAYO;
use mayo_c_sys::mayo::{MAYO, MAYOParameterSet};

impl BlindSignatureConservative {
    /// Initializes the blind signature and determines all the parameters for the
    /// construction. There are three different security levels (128, 192, 256).
    /// According to them, the respective versions for the zero-knwoledge proof and MAYO
    /// (MAYO1, MAYO3, MAYO5) are selected. Furthermore, there are different versions of
    /// the zero-knowledge proof to choose from for each of the security levels
    /// (fast, slow and additionally, version 1 and 2 for each).
    /// All of these options are captured by the enum ZKType that is provided as input to
    /// this function.
    ///
    /// # Parameters
    /// - `security_level`: Selects the bit-level security and the version of the
    ///   zero-knowledge proof that is intended to be used.
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative::zk::ZKType;
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV2_128);
    /// ```
    pub fn setup(security_level: ZKType) -> Self {
        let mayo_param = match security_level {
            ZKType::FV1_128 => MAYOParameterSet::MAYO1,
            ZKType::FV1_192 => MAYOParameterSet::MAYO3,
            ZKType::FV1_256 => MAYOParameterSet::MAYO5,
            ZKType::FV2_128 => MAYOParameterSet::MAYO1,
            ZKType::FV2_192 => MAYOParameterSet::MAYO3,
            ZKType::FV2_256 => MAYOParameterSet::MAYO5,
            ZKType::SV1_128 => MAYOParameterSet::MAYO1,
            ZKType::SV1_192 => MAYOParameterSet::MAYO3,
            ZKType::SV1_256 => MAYOParameterSet::MAYO5,
            ZKType::SV2_128 => MAYOParameterSet::MAYO1,
            ZKType::SV2_192 => MAYOParameterSet::MAYO3,
            ZKType::SV2_256 => MAYOParameterSet::MAYO5,
        };
        Self {
            lambda: match security_level {
                ZKType::FV1_128 => 128,
                ZKType::FV1_192 => 192,
                ZKType::FV1_256 => 256,
                ZKType::FV2_128 => 128,
                ZKType::FV2_192 => 192,
                ZKType::FV2_256 => 256,
                ZKType::SV1_128 => 128,
                ZKType::SV1_192 => 192,
                ZKType::SV1_256 => 256,
                ZKType::SV2_128 => 128,
                ZKType::SV2_192 => 192,
                ZKType::SV2_256 => 256,
            },
            mayo: MAYO::setup(mayo_param),
            vole_keccak_then_mayo: VOLEKeccakThenMAYO::setup(security_level),
        }
    }
}
