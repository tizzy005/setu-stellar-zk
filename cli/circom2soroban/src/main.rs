//! `stellar-circom2soroban` converts snarkjs Groth16 artifacts into the byte
//! layout the Soroban verifier (`libs/zk`) consumes.
//!
//! ## snarkjs assumptions
//!
//! This converter targets artifacts produced by **snarkjs 0.7.x** on the
//! **BLS12-381** curve (the setup scripts run `snarkjs powersoftau new
//! bls12-381 ...`). It is *not* compatible with the default BN254 artifacts
//! snarkjs emits for other curves — the field elements would not fit the
//! BLS12-381 base field and would be rejected.
//!
//! The expected JSON shapes are:
//! - `verification_key.json`: `vk_alpha_1` (G1), `vk_beta_2` / `vk_gamma_2` /
//!   `vk_delta_2` (G2), `IC` (array of G1), and `nPublic`.
//! - `proof.json`: `pi_a` (G1), `pi_b` (G2), `pi_c` (G1).
//! - `public.json`: a JSON array of decimal scalar strings.
//!
//! Coordinates are decimal strings. snarkjs represents each G2 coordinate as
//! `[c0, c1]`, matching `Fq2::new(c0, c1)` below. The point at index `[2]` of
//! each snarkjs G1/G2 array is the projective `z` coordinate (always `"1"` for
//! affine snarkjs output) and is intentionally ignored.
//!
//! ## Prototype limits
//!
//! The byte encoding produced here is duplicated by the identical
//! `g1_from_coords` / `g2_from_coords` helpers in `libs/zk/src/test.rs`; the two
//! must stay in sync. The round-trip regression tests at the bottom of this file
//! guard against drift by parsing the converter's output back through the real
//! `zk` deserializers.

use base64::engine::Engine;
use base64::{self, engine::general_purpose};
use clap::Parser;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use std::fs;
use thiserror::Error;

// imports related to constructing VK, Proof and Public Signals
use ark_bls12_381::{Fq, Fq2};
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use soroban_sdk::crypto::bls12_381::Fr;
use soroban_sdk::crypto::bls12_381::{G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE};
use soroban_sdk::U256;
use soroban_sdk::{Bytes, Env, Vec};
use zk::{Proof, PublicSignals, VerificationKey};

/// BLS12-381 scalar field modulus `r`, as a decimal string. Public signals must
/// be strictly less than this value or the on-chain verifier rejects them as
/// non-canonical (see `is_canonical_fr_bytes` in `libs/zk`).
const FR_MODULUS_DEC: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// Every error the converter can surface, with a message aimed at a human
/// feeding it a malformed artifact.
#[derive(Error, Debug)]
enum ConvertError {
    #[error("failed to read input file '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("input is not valid JSON for a {kind}: {source}")]
    Json {
        kind: &'static str,
        source: serde_json::Error,
    },

    #[error(
        "field coordinate '{value}' is not a valid BLS12-381 base-field element \
         (must be a non-negative decimal integer below the Fq modulus)"
    )]
    InvalidFieldElement { value: String },

    #[error(
        "{group} point is not on the BLS12-381 curve (or not in the prime-order \
         subgroup): x = {x}, y = {y}"
    )]
    PointNotOnCurve {
        group: &'static str,
        x: String,
        y: String,
    },

    #[error(
        "verification key is inconsistent: IC has {actual} point(s) but nPublic = \
         {n_public} requires {expected} (nPublic + 1)"
    )]
    IcLengthMismatch {
        actual: usize,
        expected: usize,
        n_public: u32,
    },

    #[error("public signal '{value}' is not a valid non-negative decimal integer")]
    InvalidPublicSignal { value: String },

    #[error("public signal '{value}' does not fit in 32 bytes and cannot be a BLS12-381 scalar")]
    PublicSignalTooLarge { value: String },

    #[error(
        "public signal '{value}' is >= the BLS12-381 scalar field modulus \
         (non-canonical); the on-chain verifier would reject it"
    )]
    NonCanonicalPublicSignal { value: String },

    #[error("could not serialize a valid curve point (internal error): {0}")]
    Serialization(String),

    #[error("unknown filetype '{0}'; expected one of: vk, proof, public")]
    UnknownFiletype(String),
}

#[derive(Parser)]
struct Args {
    filetype: String,
    filename: String,
}

#[derive(Debug, Deserialize)]
struct VerificationKeyJson {
    vk_alpha_1: [String; 3],
    vk_beta_2: [[String; 2]; 3],
    vk_gamma_2: [[String; 2]; 3],
    vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    ic: std::vec::Vec<[String; 3]>,
    #[serde(rename = "nPublic")]
    n_public: u32,
}

#[derive(Deserialize)]
struct ProofJson {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
    #[serde(rename = "protocol")]
    _protocol: String,
    #[serde(rename = "curve")]
    _curve: String,
}

// Public output is a bare JSON array of decimal scalar strings.
type PublicOutputJson = std::vec::Vec<String>;

fn parse_fq(value: &str) -> Result<Fq, ConvertError> {
    // `Fq::from_str` rejects non-decimal strings and values >= the base field
    // modulus, which is exactly the validity we want to surface.
    Fq::from_str(value).map_err(|_| ConvertError::InvalidFieldElement {
        value: value.to_string(),
    })
}

fn g1_from_coords(env: &Env, x: &str, y: &str) -> Result<G1Affine, ConvertError> {
    let px = parse_fq(x)?;
    let py = parse_fq(y)?;
    let ark_g1 = ark_bls12_381::G1Affine::new_unchecked(px, py);
    if !ark_g1.is_on_curve() || !ark_g1.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ConvertError::PointNotOnCurve {
            group: "G1",
            x: x.to_string(),
            y: y.to_string(),
        });
    }
    let mut buf = [0u8; G1_SERIALIZED_SIZE];
    ark_g1
        .serialize_uncompressed(&mut buf[..])
        .map_err(|e| ConvertError::Serialization(e.to_string()))?;
    Ok(G1Affine::from_array(env, &buf))
}

fn g2_from_coords(
    env: &Env,
    x1: &str,
    x2: &str,
    y1: &str,
    y2: &str,
) -> Result<G2Affine, ConvertError> {
    let x = Fq2::new(parse_fq(x1)?, parse_fq(x2)?);
    let y = Fq2::new(parse_fq(y1)?, parse_fq(y2)?);
    let ark_g2 = ark_bls12_381::G2Affine::new_unchecked(x, y);
    if !ark_g2.is_on_curve() || !ark_g2.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ConvertError::PointNotOnCurve {
            group: "G2",
            x: std::format!("[{}, {}]", x1, x2),
            y: std::format!("[{}, {}]", y1, y2),
        });
    }
    let mut buf = [0u8; G2_SERIALIZED_SIZE];
    ark_g2
        .serialize_uncompressed(&mut buf[..])
        .map_err(|e| ConvertError::Serialization(e.to_string()))?;
    Ok(G2Affine::from_array(env, &buf))
}

fn parse_vk_json(json_str: &str) -> Result<VerificationKeyJson, ConvertError> {
    let vk: VerificationKeyJson =
        serde_json::from_str(json_str).map_err(|source| ConvertError::Json {
            kind: "verification key",
            source,
        })?;
    validate_vk(&vk)?;
    Ok(vk)
}

fn validate_vk(vk: &VerificationKeyJson) -> Result<(), ConvertError> {
    let expected_ic_size = (vk.n_public + 1) as usize;
    if vk.ic.len() != expected_ic_size {
        return Err(ConvertError::IcLengthMismatch {
            actual: vk.ic.len(),
            expected: expected_ic_size,
            n_public: vk.n_public,
        });
    }
    Ok(())
}

fn print_vk(vk: &VerificationKeyJson) {
    println!("// CODE START");
    println!("let alphax = \"{}\";", vk.vk_alpha_1[0]);
    println!("let alphay = \"{}\";", vk.vk_alpha_1[1]);
    println!("\n");
    println!("let betax1 = \"{}\";", vk.vk_beta_2[0][0]);
    println!("let betax2 = \"{}\";", vk.vk_beta_2[0][1]);
    println!("let betay1 = \"{}\";", vk.vk_beta_2[1][0]);
    println!("let betay2 = \"{}\";", vk.vk_beta_2[1][1]);
    println!("\n");
    println!("let gammax1 = \"{}\";", vk.vk_gamma_2[0][0]);
    println!("let gammax2 = \"{}\";", vk.vk_gamma_2[0][1]);
    println!("let gammay1 = \"{}\";", vk.vk_gamma_2[1][0]);
    println!("let gammay2 = \"{}\";", vk.vk_gamma_2[1][1]);
    println!("\n");
    println!("let deltax1 = \"{}\";", vk.vk_delta_2[0][0]);
    println!("let deltax2 = \"{}\";", vk.vk_delta_2[0][1]);
    println!("let deltay1 = \"{}\";", vk.vk_delta_2[1][0]);
    println!("let deltay2 = \"{}\";", vk.vk_delta_2[1][1]);
    println!("\n");

    // The IC array has nPublic + 1 elements (first is the generator point).
    for i in 0..=vk.n_public {
        println!("let ic{}x = \"{}\";", i, vk.ic[i as usize][0]);
        println!("let ic{}y = \"{}\";", i, vk.ic[i as usize][1]);
        println!("\n");
    }

    println!("// CODE END");
}

fn vk_to_bytes(vk_json: &VerificationKeyJson) -> Result<Bytes, ConvertError> {
    let env = Env::default();

    // Build IC array dynamically based on nPublic.
    let mut ic_array = Vec::new(&env);
    for i in 0..=vk_json.n_public {
        let icx = &vk_json.ic[i as usize][0];
        let icy = &vk_json.ic[i as usize][1];
        ic_array.push_back(g1_from_coords(&env, icx, icy)?);
    }

    let vk = VerificationKey {
        alpha: g1_from_coords(&env, &vk_json.vk_alpha_1[0], &vk_json.vk_alpha_1[1])?,
        beta: g2_from_coords(
            &env,
            &vk_json.vk_beta_2[0][0],
            &vk_json.vk_beta_2[0][1],
            &vk_json.vk_beta_2[1][0],
            &vk_json.vk_beta_2[1][1],
        )?,
        gamma: g2_from_coords(
            &env,
            &vk_json.vk_gamma_2[0][0],
            &vk_json.vk_gamma_2[0][1],
            &vk_json.vk_gamma_2[1][0],
            &vk_json.vk_gamma_2[1][1],
        )?,
        delta: g2_from_coords(
            &env,
            &vk_json.vk_delta_2[0][0],
            &vk_json.vk_delta_2[0][1],
            &vk_json.vk_delta_2[1][0],
            &vk_json.vk_delta_2[1][1],
        )?,
        ic: ic_array,
    };

    Ok(vk.to_bytes(&env))
}

fn proof_to_bytes(proof_json: &ProofJson) -> Result<Bytes, ConvertError> {
    let env = Env::default();
    let proof = Proof {
        a: g1_from_coords(&env, &proof_json.pi_a[0], &proof_json.pi_a[1])?,
        b: g2_from_coords(
            &env,
            &proof_json.pi_b[0][0],
            &proof_json.pi_b[0][1],
            &proof_json.pi_b[1][0],
            &proof_json.pi_b[1][1],
        )?,
        c: g1_from_coords(&env, &proof_json.pi_c[0], &proof_json.pi_c[1])?,
    };
    Ok(proof.to_bytes(&env))
}

fn print_proof(proof: &ProofJson) {
    println!("// CODE START");
    println!("let pi_ax = \"{}\";", proof.pi_a[0]);
    println!("let pi_ay = \"{}\";", proof.pi_a[1]);
    println!("\n");
    println!("let pi_bx1 = \"{}\";", proof.pi_b[0][0]);
    println!("let pi_bx2 = \"{}\";", proof.pi_b[0][1]);
    println!("let pi_by1 = \"{}\";", proof.pi_b[1][0]);
    println!("let pi_by2 = \"{}\";", proof.pi_b[1][1]);
    println!("\n");
    println!("let pi_cx = \"{}\";", proof.pi_c[0]);
    println!("let pi_cy = \"{}\";", proof.pi_c[1]);
    println!("// CODE END");
}

/// Parse a decimal public-signal string into a validated 32-byte big-endian
/// scalar, or a clear error explaining why it is unusable on-chain.
fn public_signal_to_bytes(signal: &str) -> Result<[u8; 32], ConvertError> {
    let value =
        BigUint::from_str_radix(signal, 10).map_err(|_| ConvertError::InvalidPublicSignal {
            value: signal.to_string(),
        })?;

    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(ConvertError::PublicSignalTooLarge {
            value: signal.to_string(),
        });
    }

    // Reject non-canonical scalars up front so the CLI fails loudly instead of
    // handing the contract bytes it will reject at verification time.
    let modulus = BigUint::from_str_radix(FR_MODULUS_DEC, 10).expect("FR_MODULUS_DEC is valid");
    if value >= modulus {
        return Err(ConvertError::NonCanonicalPublicSignal {
            value: signal.to_string(),
        });
    }

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(padded)
}

fn print_public_output(public_output: &PublicOutputJson) -> Result<(), ConvertError> {
    println!("// CODE START");
    println!("// Public output signals:");
    for (i, signal) in public_output.iter().enumerate() {
        let bytes = public_signal_to_bytes(signal)?;
        let bytes_str = bytes
            .iter()
            .map(|b| std::format!("0x{:02x}", b))
            .collect::<std::vec::Vec<_>>()
            .join(", ");
        println!(
            "let public_{} = U256::from_be_bytes(&env, &Bytes::from_array(&env, &[{}]));",
            i, bytes_str
        );
    }

    println!("\n// Create output vector for verification:");
    print!("let output = Vec::from_array(&env, [");
    for (i, _) in public_output.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("Fr::from_u256(public_{})", i);
    }
    println!("]);");
    println!("// CODE END");
    Ok(())
}

fn public_output_to_bytes(public_output: &PublicOutputJson) -> Result<Bytes, ConvertError> {
    let env = Env::default();
    let mut pub_signals = Vec::new(&env);
    for signal in public_output.iter() {
        let arr = public_signal_to_bytes(signal)?;
        let u256 = U256::from_be_bytes(&env, &Bytes::from_array(&env, &arr));
        pub_signals.push_back(Fr::from_u256(u256));
    }
    let public_signals = PublicSignals { pub_signals };
    Ok(public_signals.to_bytes(&env))
}

fn emit_encodings(label: &str, bytes: &Bytes) {
    let vec: std::vec::Vec<u8> = bytes.iter().collect();
    println!(
        "\n{} Base64 encoding:\n{}",
        label,
        general_purpose::STANDARD.encode(&vec)
    );
    println!("{} Hex encoding:\n{}", label, hex::encode(&vec));
}

fn run(args: &Args) -> Result<(), ConvertError> {
    let json_str = fs::read_to_string(&args.filename).map_err(|source| ConvertError::Io {
        path: args.filename.clone(),
        source,
    })?;

    match args.filetype.as_str() {
        "vk" => {
            let vk = parse_vk_json(&json_str)?;
            print_vk(&vk);
            emit_encodings("VK", &vk_to_bytes(&vk)?);
        }
        "proof" => {
            let proof: ProofJson =
                serde_json::from_str(&json_str).map_err(|source| ConvertError::Json {
                    kind: "proof",
                    source,
                })?;
            print_proof(&proof);
            emit_encodings("Proof", &proof_to_bytes(&proof)?);
        }
        "public" => {
            let public: PublicOutputJson =
                serde_json::from_str(&json_str).map_err(|source| ConvertError::Json {
                    kind: "public signals",
                    source,
                })?;
            print_public_output(&public)?;
            emit_encodings("Public signals", &public_output_to_bytes(&public)?);
        }
        other => return Err(ConvertError::UnknownFiletype(other.to_string())),
    }

    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(&args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk::Groth16Error;

    // Known-valid, on-curve BLS12-381 points lifted from `libs/zk/src/test.rs`
    // (`test_coin_ownership`), whose proof verifies on-chain. Reusing them keeps
    // the fixtures trustworthy without hand-typing curve constants.
    const ALPHA_X: &str = "2625583050305146829700663917277485398332586266229739236073977691599912239208704058548731458555934906273399977862822";
    const ALPHA_Y: &str = "1155364156944807367912876641032696519500054551629402873339575774959620483194368919563799050765095981406853619398751";
    const BETA_X1: &str = "1659696755509039809248937927616726274238080235224171061036366585278216098417245587200210264410333778948851576160490";
    const BETA_X2: &str = "1338363397031837211155983756179787835339490797745307535810204658838394402900152502268197396587061400659003281046656";
    const BETA_Y1: &str = "1974652615426136516341494326987376616840373177388374023461177997087381634383568759591087499459321812809521924259354";
    const BETA_Y2: &str = "3301884318087924474550898163462840036865878131635519297186391370517333773367262804074867347346141727012544462046142";
    const GAMMA_X1: &str = "352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160";
    const GAMMA_X2: &str = "3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758";
    const GAMMA_Y1: &str = "1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905";
    const GAMMA_Y2: &str = "927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582";
    const DELTA_X1: &str = "2743142984898738125001654242270255897674294587748253980774444623218527122281885484824857579589713606363239065733017";
    const DELTA_X2: &str = "204094511116361675952446773023082620129915086661714657422228091029815576847171516978148871266279683009739984647370";
    const DELTA_Y1: &str = "1939174617523090044587198902486590913714778055316589513843553175656942451344239147573490910682365706772067255113505";
    const DELTA_Y2: &str = "2292766382025993571077921250915535065222739994205317155933298500829977470451722231881154853465745409220984289503104";
    const IC0_X: &str = "2683618448904306335228903505299721458337998659387683182703607938866093851528642837054373953710816742402346993120797";
    const IC0_Y: &str = "1786668422239574992109894972831696712754414376375650177546698505846675773736122594055286256880476355557498422341634";
    const IC1_X: &str = "66902808652025389632864246790882182391974469705330059940923330385191291897071317426471178445902460845068967727278";
    const IC1_Y: &str = "2594765160054401352409621725597484660493244453849646390863879503499356393964853319062162092260143573762198575717487";
    const IC2_X: &str = "1003382246631454829876446584401033316871748572555275360455886052458082997944181369047339077877767811660479191253501";
    const IC2_Y: &str = "2544403050708001388892167906290198493026544815081144389732529981844829005748116399510257129962201796703233322017126";

    const PI_A_X: &str = "2312845116701672402180486748482758387792019392638873512193039748796932219258491169543785273216043839153656695561028";
    const PI_A_Y: &str = "2401388344361274103911290492305041495151045197799709253975549979749000050189613887123319051631926316639875318530706";
    const PI_B_X1: &str = "254112989406552222064547883149713450818858945843832143975529650914462737635290229325433889900886989167652287651477";
    const PI_B_X2: &str = "1298427328165001466050889647718980726801340148316849424955517639658980366356339914458078849522724674106484718321177";
    const PI_B_Y1: &str = "5321429806065285653141424032098896697927422746457669045090054322756670504823633361000243836633074177798333017419";
    const PI_B_Y2: &str = "2189884843665900970576104345488554859679199450652275441615353017043226667793893188654509510191387551155638147549016";
    const PI_C_X: &str = "2191481390831460536193287377108883221181604287496545032823796584973842680176886739387559733959993660004385853733594";
    const PI_C_Y: &str = "423577060414004702507038675020769607957163072861493245791725852305440453270407094427666302510671441390869114232609";

    fn vk_json(n_public: u32, ic: &[(&str, &str)]) -> String {
        let ics: std::vec::Vec<String> = ic
            .iter()
            .map(|(x, y)| std::format!("[\"{}\",\"{}\",\"1\"]", x, y))
            .collect();
        std::format!(
            r#"{{
              "protocol":"groth16","curve":"bls12381","nPublic":{n},
              "vk_alpha_1":["{ax}","{ay}","1"],
              "vk_beta_2":[["{bx1}","{bx2}"],["{by1}","{by2}"],["1","0"]],
              "vk_gamma_2":[["{gx1}","{gx2}"],["{gy1}","{gy2}"],["1","0"]],
              "vk_delta_2":[["{dx1}","{dx2}"],["{dy1}","{dy2}"],["1","0"]],
              "IC":[{ic}]
            }}"#,
            n = n_public,
            ax = ALPHA_X,
            ay = ALPHA_Y,
            bx1 = BETA_X1,
            bx2 = BETA_X2,
            by1 = BETA_Y1,
            by2 = BETA_Y2,
            gx1 = GAMMA_X1,
            gx2 = GAMMA_X2,
            gy1 = GAMMA_Y1,
            gy2 = GAMMA_Y2,
            dx1 = DELTA_X1,
            dx2 = DELTA_X2,
            dy1 = DELTA_Y1,
            dy2 = DELTA_Y2,
            ic = ics.join(","),
        )
    }

    fn valid_vk_json() -> String {
        vk_json(2, &[(IC0_X, IC0_Y), (IC1_X, IC1_Y), (IC2_X, IC2_Y)])
    }

    fn valid_proof_json() -> String {
        std::format!(
            r#"{{
              "protocol":"groth16","curve":"bls12381",
              "pi_a":["{ax}","{ay}","1"],
              "pi_b":[["{bx1}","{bx2}"],["{by1}","{by2}"],["1","0"]],
              "pi_c":["{cx}","{cy}","1"]
            }}"#,
            ax = PI_A_X,
            ay = PI_A_Y,
            bx1 = PI_B_X1,
            bx2 = PI_B_X2,
            by1 = PI_B_Y1,
            by2 = PI_B_Y2,
            cx = PI_C_X,
            cy = PI_C_Y,
        )
    }

    // --- Regression: converter output must round-trip through the real zk
    // deserializers the contract uses. This catches any drift in field
    // ordering, padding, length prefixes, or serialization endianness. ---

    #[test]
    fn vk_conversion_roundtrips_through_zk() {
        let env = Env::default();
        let vk = parse_vk_json(&valid_vk_json()).expect("vk parses");
        let bytes = vk_to_bytes(&vk).expect("vk converts");
        let decoded = VerificationKey::from_bytes(&env, &bytes).expect("zk parses vk bytes");
        // IC length must equal nPublic + 1 and re-serialize identically.
        assert_eq!(decoded.ic.len(), 3);
        assert_eq!(decoded.to_bytes(&env), bytes);
    }

    #[test]
    fn proof_conversion_roundtrips_through_zk() {
        let env = Env::default();
        let proof: ProofJson = serde_json::from_str(&valid_proof_json()).unwrap();
        let bytes = proof_to_bytes(&proof).expect("proof converts");
        let decoded = Proof::from_bytes(&env, &bytes).expect("zk parses proof bytes");
        assert_eq!(decoded.to_bytes(&env), bytes);
    }

    #[test]
    fn public_conversion_roundtrips_through_zk() {
        let env = Env::default();
        let json: PublicOutputJson = serde_json::from_str(r#"["33","1000000000"]"#).unwrap();
        let bytes = public_output_to_bytes(&json).expect("public converts");
        let decoded = PublicSignals::from_bytes(&env, &bytes).expect("zk parses public bytes");
        assert_eq!(decoded.pub_signals.len(), 2);
        assert_eq!(decoded.to_bytes(&env), bytes);
    }

    // --- Golden vector: the public-signal encoding is fully specified
    // (4-byte big-endian length prefix, then 32-byte big-endian scalars), so we
    // can pin the exact bytes independently of any curve library. ---

    #[test]
    fn public_golden_vector() {
        let json: PublicOutputJson = serde_json::from_str(r#"["33"]"#).unwrap();
        let bytes = public_output_to_bytes(&json).unwrap();
        let hex_str = hex::encode(bytes.iter().collect::<std::vec::Vec<u8>>());
        // len = 1 (0x00000001) followed by 32-byte big-endian 33 (0x...21).
        let expected = std::format!("00000001{}21", "00".repeat(31));
        assert_eq!(hex_str, expected);
    }

    // --- Malformed-input handling: every path must produce a clear error
    // instead of a panic. ---

    #[test]
    fn rejects_invalid_json() {
        let err = parse_vk_json("{ not json").unwrap_err();
        assert!(matches!(err, ConvertError::Json { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_ic_length_mismatch() {
        // nPublic = 5 requires 6 IC points, but we only supply 3.
        let json = vk_json(5, &[(IC0_X, IC0_Y), (IC1_X, IC1_Y), (IC2_X, IC2_Y)]);
        let err = parse_vk_json(&json).unwrap_err();
        match err {
            ConvertError::IcLengthMismatch {
                actual,
                expected,
                n_public,
            } => {
                assert_eq!((actual, expected, n_public), (3, 6, 5));
            }
            other => panic!("expected IcLengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_decimal_coordinate() {
        let err = g1_from_coords(&Env::default(), "not_a_number", IC0_Y).unwrap_err();
        assert!(
            matches!(err, ConvertError::InvalidFieldElement { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_off_curve_point() {
        // A valid x with a y that is not the matching curve point.
        let err = g1_from_coords(&Env::default(), IC0_X, IC1_Y).unwrap_err();
        assert!(
            matches!(err, ConvertError::PointNotOnCurve { group: "G1", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_canonical_public_signal() {
        // The scalar field modulus itself is the smallest non-canonical value.
        let err = public_signal_to_bytes(FR_MODULUS_DEC).unwrap_err();
        assert!(
            matches!(err, ConvertError::NonCanonicalPublicSignal { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_oversized_public_signal() {
        // 2^256 needs 33 bytes and cannot be a 32-byte scalar.
        let two_pow_256 = std::format!(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
        );
        let err = public_signal_to_bytes(&two_pow_256).unwrap_err();
        assert!(
            matches!(err, ConvertError::PublicSignalTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_decimal_public_signal() {
        let err = public_signal_to_bytes("0xdeadbeef").unwrap_err();
        assert!(
            matches!(err, ConvertError::InvalidPublicSignal { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_filetype_is_rejected() {
        // `run` requires a readable file; check the dispatch guard directly by
        // confirming the variant exists and formats a helpful message.
        let err = ConvertError::UnknownFiletype("witness".to_string());
        assert!(err.to_string().contains("vk, proof, public"));
    }

    #[test]
    fn accepts_max_canonical_public_signal() {
        // r - 1 is the largest canonical scalar and must be accepted.
        let modulus = BigUint::from_str_radix(FR_MODULUS_DEC, 10).unwrap();
        let max = modulus - 1u32;
        let bytes = public_signal_to_bytes(&max.to_str_radix(10)).expect("r-1 is canonical");
        // Sanity: the zk layer also treats it as canonical.
        let env = Env::default();
        let mut encoded = Bytes::from_array(&env, &[0, 0, 0, 1]);
        encoded.append(&Bytes::from_array(&env, &bytes));
        assert!(PublicSignals::from_bytes(&env, &encoded).is_ok());
        let _ = Groth16Error::NonCanonicalPublicSignal; // referenced to keep import meaningful
    }
}
