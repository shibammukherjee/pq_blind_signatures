use crate::zk::ZKType;

use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo128fv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo128fv2_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo128sv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo128sv2_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo192fv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo192fv2_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo192sv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo192sv2_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo256fv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo256fv2_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo256sv1_parameters;
use vole_keccak_deg16_then_mayo_sys::get_keccak_then_mayo256sv2_parameters;

use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128fv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128fv2_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128sv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128sv2_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192fv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192fv2_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192sv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192sv2_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256fv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256fv2_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256sv1_prove;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256sv2_prove;

use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128fv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128fv2_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128sv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo128sv2_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192fv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192fv2_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192sv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo192sv2_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256fv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256fv2_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256sv1_verify;
use vole_keccak_deg16_then_mayo_sys::keccak_then_mayo256sv2_verify;

pub struct VOLEKeccakDeg16ThenMAYOParameters {
    pub chal1_size: usize,
    pub r_size: usize,
    pub u_size: usize,
    pub v_size: usize,
    pub forest_size: usize,
    pub iv_pre_size: usize,
    pub hashed_leaves_size: usize,
    pub proof_size: usize,
    pub proof1_size: usize,
    pub packed_pk_size: usize,
    pub packed_sk_size: usize,
    pub random_seed_size: usize,
    pub pk_seed_size: usize,
    pub p1_size: usize,
    pub p2_size: usize,
    pub p3_size: usize,
    pub h_size: usize,
    pub s_size: usize,
    pub prove_fn: ProveFn,
    pub verify_fn: VerifyFn,
}

type GetParamsFn = unsafe extern "C" fn(
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
    *mut usize,
);

type ProveFn = unsafe extern "C" fn(
    *mut u8,
    *const u8,
    usize,
    *mut u8,
    *mut u8,
    *mut u8,
    *mut u8,
    *mut u8,
    *mut u8,
) -> bool;

type VerifyFn = unsafe extern "C" fn(*const u8, usize, *mut u8, *mut u8, *mut u8) -> bool;

impl VOLEKeccakDeg16ThenMAYOParameters {
    pub fn setup(params: ZKType) -> Self {
        let mut chal1_size = 0usize;
        let mut r_size = 0usize;
        let mut u_size = 0usize;
        let mut v_size = 0usize;
        let mut forest_size = 0usize;
        let mut iv_pre_size = 0usize;
        let mut hashed_leaves_size = 0usize;
        let mut proof_size = 0usize;
        let mut proof1_size = 0usize;
        let mut packed_pk_size = 0usize;
        let mut packed_sk_size = 0usize;
        let mut random_seed_size = 0usize;
        let mut pk_seed_size = 0usize;
        let mut p1_size = 0usize;
        let mut p2_size = 0usize;
        let mut p3_size = 0usize;
        let mut h_size = 0usize;
        let mut s_size = 0usize;

        let get_params_fun: GetParamsFn =
            VOLEKeccakDeg16ThenMAYOParameters::get_get_params_function(params);

        unsafe {
            get_params_fun(
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

        Self {
            chal1_size,
            r_size,
            u_size,
            v_size,
            forest_size,
            iv_pre_size,
            hashed_leaves_size,
            proof_size,
            proof1_size,
            packed_pk_size,
            packed_sk_size,
            random_seed_size,
            pk_seed_size,
            p1_size,
            p2_size,
            p3_size,
            h_size,
            s_size,
            prove_fn: VOLEKeccakDeg16ThenMAYOParameters::get_prove_function(params),
            verify_fn: VOLEKeccakDeg16ThenMAYOParameters::get_verify_function(params),
        }
    }

    fn get_get_params_function(params: ZKType) -> GetParamsFn {
        match params {
            ZKType::FV1_128 => get_keccak_then_mayo128fv1_parameters,
            ZKType::FV1_192 => get_keccak_then_mayo192fv1_parameters,
            ZKType::FV1_256 => get_keccak_then_mayo256fv1_parameters,
            ZKType::FV2_128 => get_keccak_then_mayo128fv2_parameters,
            ZKType::FV2_192 => get_keccak_then_mayo192fv2_parameters,
            ZKType::FV2_256 => get_keccak_then_mayo256fv2_parameters,
            ZKType::SV1_128 => get_keccak_then_mayo128sv1_parameters,
            ZKType::SV1_192 => get_keccak_then_mayo192sv1_parameters,
            ZKType::SV1_256 => get_keccak_then_mayo256sv1_parameters,
            ZKType::SV2_128 => get_keccak_then_mayo128sv2_parameters,
            ZKType::SV2_192 => get_keccak_then_mayo192sv2_parameters,
            ZKType::SV2_256 => get_keccak_then_mayo256sv2_parameters,
        }
    }

    fn get_prove_function(params: ZKType) -> ProveFn {
        match params {
            ZKType::FV1_128 => keccak_then_mayo128fv1_prove,
            ZKType::FV1_192 => keccak_then_mayo192fv1_prove,
            ZKType::FV1_256 => keccak_then_mayo256fv1_prove,
            ZKType::FV2_128 => keccak_then_mayo128fv2_prove,
            ZKType::FV2_192 => keccak_then_mayo192fv2_prove,
            ZKType::FV2_256 => keccak_then_mayo256fv2_prove,
            ZKType::SV1_128 => keccak_then_mayo128sv1_prove,
            ZKType::SV1_192 => keccak_then_mayo192sv1_prove,
            ZKType::SV1_256 => keccak_then_mayo256sv1_prove,
            ZKType::SV2_128 => keccak_then_mayo128sv2_prove,
            ZKType::SV2_192 => keccak_then_mayo192sv2_prove,
            ZKType::SV2_256 => keccak_then_mayo256sv2_prove,
        }
    }

    fn get_verify_function(params: ZKType) -> VerifyFn {
        match params {
            ZKType::FV1_128 => keccak_then_mayo128fv1_verify,
            ZKType::FV1_192 => keccak_then_mayo192fv1_verify,
            ZKType::FV1_256 => keccak_then_mayo256fv1_verify,
            ZKType::FV2_128 => keccak_then_mayo128fv2_verify,
            ZKType::FV2_192 => keccak_then_mayo192fv2_verify,
            ZKType::FV2_256 => keccak_then_mayo256fv2_verify,
            ZKType::SV1_128 => keccak_then_mayo128sv1_verify,
            ZKType::SV1_192 => keccak_then_mayo192sv1_verify,
            ZKType::SV1_256 => keccak_then_mayo256sv1_verify,
            ZKType::SV2_128 => keccak_then_mayo128sv2_verify,
            ZKType::SV2_192 => keccak_then_mayo192sv2_verify,
            ZKType::SV2_256 => keccak_then_mayo256sv2_verify,
        }
    }
}
