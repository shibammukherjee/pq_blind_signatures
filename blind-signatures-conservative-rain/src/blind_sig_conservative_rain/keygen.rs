use super::{BlindSignatureConservativeRain, PkType, SkType};

impl BlindSignatureConservativeRain {
    /// Executes the key generation for MAYO and returns the respective keys
    /// Both keys are compressed.
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative_rain::zk::ZKType;
    /// use blind_signatures_conservative_rain::blind_sig_conservative_rain::BlindSignatureConservativeRain;
    ///
    /// let bs = BlindSignatureConservativeRain::setup(ZKType::FV1_128);
    /// let (pk, sk) = bs.keygen();
    /// ```
    pub fn keygen(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }
}
