//! The commitment scheme used within the blind signature.

use vole_rainhash_then_mayo_sys::rain_hash_512_7_c;

pub type CommitmentType = Vec<u8>;
pub type CommitmentMessageType = Vec<u8>;
pub type CommitmentRandomnessType = Vec<u8>;

/// Hash-commitments using RainHash
/// The two inputs are concatenated and its hash value is returned
/// The maximal input and output size is 64 Bytes.
///
/// # Params
/// - `m`: the message of fixed length lambda
/// - `r`: the randomness of fixed length lambda
/// - `output_len`: the length of the hash output in bytes
///
/// Returns `rain(m||r)`
///
/// # Example
/// ```
/// use blind_signatures_conservative_rain::commitment::rain_commitment;
/// let m = vec![42;21];
/// let r = vec![0;10];
///
/// let com = rain_commitment(&m, &r, 32);
/// ```
pub fn rain_commitment(
    m: &CommitmentMessageType,
    r: &CommitmentRandomnessType,
    output_len: usize,
) -> CommitmentType {
    assert!(output_len <= 64);
    let mut output = vec![0; output_len];

    // println!("m {:?}", m);
    // println!("m: {}", m.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    // println!("r {:?}", r);
    // println!("r: {}", r.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    let mut input = Vec::with_capacity(64);
    input.extend(m);
    input.extend(r);
    assert_eq!(m.len() + r.len(), 32);
    input.extend(vec![0xff; 64 - m.len() - r.len()]);

    // println!("input {:?}", input);

    unsafe { rain_hash_512_7_c(output.as_mut_ptr(), output_len, input.as_ptr(), input.len()) };

    // println!("output: {}", output.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    output
}
