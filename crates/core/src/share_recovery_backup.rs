//! Share recovery with encrypted backup implementation.
//!
//! Ref: <https://wamu.tech/specification#share-recovery-backup>.
//!
//! [HKDF (HMAC-based Extract-and-Expand Key Derivation Function)](https://tools.ietf.org/html/rfc5869) and
//! [AES-GCM (Advanced Encryption Standard Galois/Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
//! are the key derivation function and symmetric encryption algorithm used respectively.

use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, AesGcm,
};
use crypto_bigint::{Encoding, U256};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::ShareBackupRecoveryError;
use crate::payloads::EncryptedShareBackup;
use crate::share::{SigningShare, SubShare};
use crate::traits::IdentityProvider;

/// Given an entropy seed (i.e typically a standardized phrase), "signing share", "sub-share" and identity provider,
/// returns an ok result including the encrypted share backup (i.e an encrypted "signing share" and "sub-share", and a random nonce)
/// or an encryption error result.
///
/// Ref: <https://wamu.tech/specification#share-recovery-backup-encrypt>.
pub fn backup(
    entropy_seed: &[u8],
    signing_share: &SigningShare,
    sub_share: &SubShare,
    identity_provider: &impl IdentityProvider,
) -> Result<EncryptedShareBackup, ShareBackupRecoveryError> {
    // Generates nonce.
    let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());

    // Encrypts the "signing share" and "sub-share".
    let cipher = generate_encryption_cipher(entropy_seed, identity_provider);
    let encrypted_signing_share = cipher.encrypt(&nonce, signing_share.to_be_bytes().as_ref())?;
    let encrypted_sub_share = (
        cipher.encrypt(&nonce, sub_share.x().to_be_bytes().as_ref())?,
        cipher.encrypt(&nonce, sub_share.y().to_be_bytes().as_ref())?,
    );

    // Returns the encrypted share backup.
    Ok(EncryptedShareBackup {
        signing_share: encrypted_signing_share,
        sub_share: encrypted_sub_share,
        nonce: nonce.to_vec(),
    })
}

/// Given an entropy seed (i.e typically a standardized phrase), encrypted share backup
/// (i.e an encrypted "signing share" and "sub-share", and a random nonce) and an identity provider,
/// returns the decrypted "signing share" and "sub-share".
///
/// Ref: <https://wamu.tech/specification#share-recovery-backup-decrypt>.
pub fn recover(
    entropy_seed: &[u8],
    encrypted_share_backup: &EncryptedShareBackup,
    identity_provider: &impl IdentityProvider,
) -> Result<(SigningShare, SubShare), ShareBackupRecoveryError> {
    // Generates nonce.
    let nonce = aes_gcm::Nonce::from_slice(&encrypted_share_backup.nonce);

    // Decrypts the "signing share" and "sub-share".
    let cipher = generate_encryption_cipher(entropy_seed, identity_provider);
    let signing_share_bytes =
        cipher.decrypt(nonce, encrypted_share_backup.signing_share.as_ref())?;
    let signing_share = SigningShare::try_from(signing_share_bytes.as_ref())
        .map_err(|_| ShareBackupRecoveryError::InvalidSigningShare)?;
    let sub_share = SubShare::new(
        U256::from_be_bytes(
            cipher
                .decrypt(nonce, encrypted_share_backup.sub_share.0.as_ref())?
                .try_into()
                .map_err(|_| ShareBackupRecoveryError::InvalidSubShare)?,
        ),
        U256::from_be_bytes(
            cipher
                .decrypt(nonce, encrypted_share_backup.sub_share.1.as_ref())?
                .try_into()
                .map_err(|_| ShareBackupRecoveryError::InvalidSubShare)?,
        ),
    )
    .map_err(|_| ShareBackupRecoveryError::InvalidSubShare)?;

    Ok((signing_share, sub_share))
}

/// Given an entropy seed (i.e typically a standardized phrase) and an identity provider, returns an encryption cipher.
fn generate_encryption_cipher(
    entropy_seed: &[u8],
    identity_provider: &impl IdentityProvider,
) -> AesGcm<Aes256, U12> {
    // Generates encryption key.
    let key_bytes = generate_encryption_key(entropy_seed, identity_provider);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);

    // Generates and returns cipher.
    Aes256Gcm::new(key)
}

/// Given an entropy seed (i.e typically a standardized phrase) and an identity provider, returns a 256 bit encryption secret.
fn generate_encryption_key(
    entropy_seed: &[u8],
    identity_provider: &impl IdentityProvider,
) -> [u8; 32] {
    // Generates entropy as the signature of the entropy seed phrase.
    let entropy = identity_provider.sign(entropy_seed);

    // Generates encryption key.
    let mut output_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &entropy.sig)
        .expand(&[], &mut output_key)
        .expect("32 is a valid length for Sha256 to output");

    // Returns generated encryption key.
    output_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Random32Bytes;
    use crate::share::SecretShare;
    use crate::share_split_reconstruct;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn share_recovery_with_encrypted_backup_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Set entropy seed.
        let entropy_seed = b"Hello, world!";

        // Generates secret share.
        let secret_share = SecretShare::from(Random32Bytes::generate_mod_q());

        // Computes "signing share" and "sub-share".
        let (signing_share, sub_share) =
            share_split_reconstruct::split(&secret_share, &identity_provider).unwrap();

        // Generates encryption share backup.
        let backup_result = backup(entropy_seed, &signing_share, &sub_share, &identity_provider);

        // Verifies backup result.
        assert!(backup_result.is_ok());

        // Unwraps encrypted share backup.
        let encrypted_share_backup = backup_result.unwrap();

        // Generates encryption share backup.
        let recover_result = recover(entropy_seed, &encrypted_share_backup, &identity_provider);

        // Verifies recover result.
        assert!(recover_result.is_ok());

        // Unwraps "signing share" and "sub-share" from recover result.
        let (recovered_signing_share, recovered_sub_share) = recover_result.unwrap();

        // Verifies recovered "signing share" and "sub-share".
        assert_eq!(
            &recovered_signing_share.to_be_bytes(),
            &signing_share.to_be_bytes()
        );
        assert_eq!(recovered_sub_share.as_tuple(), sub_share.as_tuple());
    }

    #[test]
    fn generate_encryption_key_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Set entropy seed.
        let entropy_seed = b"Hello, world!";

        // Generates encryption key.
        let encryption_key = generate_encryption_key(entropy_seed, &identity_provider);

        // Verifies that generated encryption key is deterministic based on the entropy seed and identity provider.
        assert_eq!(
            encryption_key,
            generate_encryption_key(entropy_seed, &identity_provider)
        );

        // Verifies that different inputs (entropy seed and identity provider) permutations produce different encryption keys.
        assert_ne!(
            encryption_key,
            generate_encryption_key(entropy_seed, &MockECDSAIdentityProvider::generate())
        );
        assert_ne!(
            encryption_key,
            generate_encryption_key(b"Another phrase.", &identity_provider)
        );
    }
}
