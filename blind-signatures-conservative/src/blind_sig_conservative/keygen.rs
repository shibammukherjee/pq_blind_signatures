use super::{BlindSignatureConservative, PkType, SkType};

impl BlindSignatureConservative {
    /// Executes the key generation for MAYO and returns the respective keys
    /// Both keys are compressed.
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative::zk::ZKType;
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV2_128);
    /// let (pk, sk) = bs.keygen();
    /// ```
    pub fn keygen(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }
}
