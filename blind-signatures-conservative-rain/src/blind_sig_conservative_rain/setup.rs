use crate::zk::vole_rain_then_mayo::VOLERainThenMAYO;
use crate::{blind_sig_conservative_rain::BlindSignatureConservativeRain, zk::ZKType};
use mayo_c_rain_sys::mayo::{MAYO, MAYOParameterSet};

impl BlindSignatureConservativeRain {
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
    /// use blind_signatures_conservative_rain::zk::ZKType;
    /// use blind_signatures_conservative_rain::blind_sig_conservative_rain::BlindSignatureConservativeRain;
    ///
    /// let bs = BlindSignatureConservativeRain::setup(ZKType::FV1_128);
    /// ```
    pub fn setup(security_level: ZKType) -> Self {
        let mayo_param = match security_level {
            ZKType::FV1_128 => MAYOParameterSet::MAYO1,
            ZKType::FV2_128 => MAYOParameterSet::MAYO1,
            ZKType::SV1_128 => MAYOParameterSet::MAYO1,
            ZKType::SV2_128 => MAYOParameterSet::MAYO1,
            _ => panic!("parameter set is not supported"),
        };
        Self {
            lambda: match security_level {
                ZKType::FV1_128 => 128,
                ZKType::FV2_128 => 128,
                ZKType::SV1_128 => 128,
                ZKType::SV2_128 => 128,
                _ => panic!("parameter set is not supported"),
            },
            mayo: MAYO::setup(mayo_param),
            vole_rain_then_mayo: VOLERainThenMAYO::setup(security_level),
        }
    }
}
