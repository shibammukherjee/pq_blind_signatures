use super::{BlindSignatureOptimized, PkType, SkType};

impl BlindSignatureOptimized {
    /// Executes the key generation for MAYO and returns the respective keys
    /// Both keys are compressed.
    ///
    /// # Example
    /// ```
    /// use blind_signatures::zk::ZKType;
    /// use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
    ///
    /// let bs = BlindSignatureOptimized::setup(ZKType::FV1_128);
    /// let (pk, sk) = bs.keygen();
    /// ```
    pub fn keygen(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }
}
