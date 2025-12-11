#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod vole_proof_test_keccak_then_mayo {
    use crate::get_keccak_then_mayo128fv1_parameters;

    #[test]
    fn test_keccak_then_mayo() {
        let mut chal1_size = 0_usize;
        let mut r_size = 0_usize;
        let mut u_size = 0_usize;
        let mut v_size = 0_usize;
        let mut forest_size = 0_usize;
        let mut iv_pre_size = 0_usize;
        let mut hashed_leaves_size = 0_usize;
        let mut proof_size = 0_usize;
        let mut proof1_size = 0_usize;
        let mut packed_pk_size = 0_usize;
        let mut packed_sk_size = 0_usize;
        let mut random_seed_size = 0_usize;
        let mut pk_seed_size = 0_usize;
        let mut p1_size = 0_usize;
        let mut p2_size = 0_usize;
        let mut p3_size = 0_usize;
        let mut h_size = 0_usize;
        let mut s_size = 0_usize;

        unsafe {
            get_keccak_then_mayo128fv1_parameters(
                &mut chal1_size,
                &mut r_size,
                &mut u_size,
                &mut v_size,
                &mut forest_size,
                &mut iv_pre_size,
                &mut hashed_leaves_size,
                &mut proof_size,
                &mut proof1_size,
                &mut packed_pk_size,
                &mut packed_sk_size,
                &mut random_seed_size,
                &mut pk_seed_size,
                &mut p1_size,
                &mut p2_size,
                &mut p3_size,
                &mut h_size,
                &mut s_size,
            )
        };
    }
}
