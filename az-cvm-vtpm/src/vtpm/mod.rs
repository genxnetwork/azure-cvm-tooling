// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tss_esapi::abstraction::{nv, pcr, public::DecodedKey};
use tss_esapi::handles::{PcrHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
use tss_esapi::structures::{Attest, AttestInfo, Data, DigestValues, Signature, SignatureScheme};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;
use std::fmt;

#[cfg(feature = "verifier")]
mod verify;

#[cfg(feature = "verifier")]
pub use verify::VerifyError;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const VTPM_AK_HANDLE: u32 = 0x81000003;
const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

fn to_pcr_handle(pcr: u8) -> Result<PcrHandle, ExtendError> {
    match pcr {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        _ => Err(ExtendError::InvalidPcr),
    }
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
}

/// Get a HCL report from an nvindex
pub fn get_report() -> Result<Vec<u8>, ReportError> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
}

#[derive(Error, Debug)]
pub enum ExtendError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("invalid pcr number (expected 0-23)")]
    InvalidPcr,
}

/// Extend a PCR register with a sha256 digest
pub fn extend_pcr(pcr: u8, digest: &[u8; 32]) -> Result<(), ExtendError> {
    let pcr_handle = to_pcr_handle(pcr)?;

    let mut vals = DigestValues::new();
    let sha256_digest = digest.to_vec().try_into()?;
    vals.set(HashingAlgorithm::Sha256, sha256_digest);

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;

    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));
    context.pcr_extend(pcr_handle, vals)?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum AKPubError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("asn1 der error")]
    WrongKeyType,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl PublicKey {
    /// Get the modulus of the public key as big-endian unsigned bytes
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// Get the public exponent of the public key as big-endian unsigned bytes
    pub fn exponent(&self) -> &[u8] {
        &self.e
    }
}

/// Get the AK pub of the vTPM
pub fn get_ak_pub() -> Result<PublicKey, AKPubError> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        return Err(AKPubError::WrongKeyType);
    };

    let bytes_n = rsa_pk.modulus.as_unsigned_bytes_be();
    let bytes_e = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let pkey = PublicKey {
        n: bytes_n.into(),
        e: bytes_e.into(),
    };
    Ok(pkey)
}

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum QuoteError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("data too large")]
    DataTooLarge,
    #[error("Not a quote, that should not occur")]
    NotAQuote,
    #[error("Wrong signature, that should not occur")]
    WrongSignature,
    #[error("PCR bank not found")]
    PcrBankNotFound,
    #[error("PCR reading error")]
    PcrRead,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
}

const SHA1_LENGTH: usize = 20;
const SHA256_LENGTH: usize = 32;

impl Algorithm {
    pub fn length(&self) -> usize {
        match self {
            Algorithm::Sha1 => SHA1_LENGTH,
            Algorithm::Sha256 => SHA256_LENGTH,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
        }
    }

    pub fn tss_esapi(&self) -> tss_esapi::interface_types::algorithm::HashingAlgorithm {
        match self {
            Algorithm::Sha1 => tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha1,
            Algorithm::Sha256 => tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
        }
    }

    pub fn digest(&self) -> &'static ring::digest::Algorithm {
        match self {
            Algorithm::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::Sha256 => &ring::digest::SHA256,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PcrBank {
    pub algo: Algorithm,
    pub pcr_values: Vec<Vec<u8>>,
}



impl PcrBank {
    pub fn get(&self, index: usize) -> Option<&Vec<u8>> {
        self.pcr_values.get(index)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Quote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcr_banks: Vec<PcrBank>,
}

impl fmt::Debug for PcrBank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{\n    algo: {:?},", self.algo)?;
        writeln!(f, "    pcr_values: [")?;
        for vec in &self.pcr_values {
            writeln!(f, "        \"{}\",", hex::encode(vec))?;
        }
        writeln!(f, "    ]\n}}")
    }
}

impl fmt::Debug for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quote")
            .field("signature", &hex::encode(&self.signature))
            .field("message", &hex::encode(&self.message))
            .field("pcr_banks", &self.pcr_banks)
            .finish()
    }
}

impl Quote {
    /// Retrieve PCR bank from a Quote
    pub fn get_pcr_bank(&self, algo: Algorithm) -> Option<&PcrBank> {
        self.pcr_banks.iter().filter(|bank| bank.algo == algo).next()
    }

    /// Extract nonce from a Quote
    pub fn nonce(&self) -> Result<Vec<u8>, QuoteError> {
        let attest = Attest::unmarshall(&self.message)?;
        let nonce = attest.extra_data().to_vec();
        Ok(nonce)
    }

    /// Extract message from a Quote
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

/// Get a signed vTPM Quote
///
/// # Arguments
///
/// * `data` - A byte slice to use as nonce
/// * `algorithms` - A list of hashing algorithms to use for the quote
pub fn get_quote(data: &[u8], algorithms: Vec<Algorithm>) -> Result<Quote, QuoteError> {
    if data.len() > Data::MAX_SIZE {
        return Err(QuoteError::DataTooLarge);
    }
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;

    let quote_data: Data = data.try_into()?;
    let scheme = SignatureScheme::Null;

    let mut selection_list = PcrSelectionListBuilder::new();
    for hash_algo in &algorithms {
        selection_list = selection_list.with_selection(hash_algo.tss_esapi(), &VTPM_QUOTE_PCR_SLOTS);
    }
    let selection_list = selection_list.build()?;

    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let (attest, signature) = context.quote(
        key_handle.into(),
        quote_data,
        scheme,
        selection_list.clone(),
    )?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(QuoteError::NotAQuote);
    };
    let Signature::RsaSsa(rsa_sig) = signature else {
        return Err(QuoteError::WrongSignature);
    };

    let signature = rsa_sig.signature().to_vec();
    let message = attest.marshall()?;

    context.clear_sessions();
    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    
    fn collect_pcrs(pcr_data: &pcr::PcrData, hash_algo: HashingAlgorithm) -> Result<Vec<Vec<u8>>, QuoteError> {
        let pcr_bank = pcr_data
            .pcr_bank(hash_algo)
            .ok_or(QuoteError::PcrBankNotFound)?;
    
        pcr_bank.into_iter()
            .map(|(_, digest)| {
                let digest_bytes = digest.value();
                Ok(digest_bytes.to_vec())
            })
            .collect()
    }

    let mut pcr_banks = Vec::new();
    for algorithm in algorithms {
        let _algorithm = algorithm.tss_esapi();
        let pcr_values = collect_pcrs(&pcr_data, _algorithm)?;
        pcr_banks.push(PcrBank { algo: algorithm, pcr_values });
    }
    
    Ok(Quote {
        signature,
        message,
        pcr_banks,
    })
}
