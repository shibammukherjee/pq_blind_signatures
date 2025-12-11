use super::{BlindSignatureConservativeDeg16, PkType, SkType};

impl BlindSignatureConservativeDeg16 {
    /// Executes the key generation for MAYO and returns the respective keys
    /// Both keys are compressed.
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative_deg16::zk::ZKType;
    /// use blind_signatures_conservative_deg16::blind_sig_conservative_deg16::BlindSignatureConservativeDeg16;
    ///
    /// let bs = BlindSignatureConservativeDeg16::setup(ZKType::FV2_128);
    /// let (pk, sk) = bs.keygen();
    /// ```
    pub fn keygen(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }
}
