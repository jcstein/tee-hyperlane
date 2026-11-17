//! Besu: a private EVM chain run by QBFT, the BFT consensus Besu recommends for permissioned
//! networks. A block is final once a quorum of its validators has commit-sealed it, so the
//! enclave checks those seals against validator addresses pinned here and takes the state
//! root from the sealed header. Nothing is re-executed; like a rollup's sequencer, the pinned
//! validators are trusted.
//!
//! The pinned validator is the devnet's, unless the build names another: `BESU_VALIDATOR` in
//! the build environment, an address as 40 hex characters, replaces it. A validator-set change
//! on the chain (a QBFT vote) needs a new image, as a sequencer key rotation does.
//!
//! What a commit seal signs (Besu's `BftBlockHashing.calculateDataHashForCommittedSeal`):
//! the keccak of the header's RLP with `extraData` re-encoded without its seals, round kept.
//! QBFT `extraData` is `rlp([vanity, validators, vote, round, seals])`. The block hash the RPC
//! reports also drops the round (`onchain_hash`), which the relayer uses to check that it
//! encoded a header the way Besu did.

use crate::state::IsmState;
use alloy_primitives::{address, hex, keccak256, Address, Bytes, Signature, B256};
use serde_json::Value;

use crate::evm::BlockHeader;
use crate::origin::{self, Chain, Head, Origin, Tree};

pub static BESU: Chain = Chain {
    name: "besu",
    domain: CHAIN_ID as u32,
    origin: &Besu {
        validators: &VALIDATORS,
    },
};

/// The devnet's chain id, which is also its Hyperlane domain.
pub const CHAIN_ID: u64 = 1_987_016_035;
/// `MerkleTreeHook` from `@hyperlane-xyz/core` 12 keeps its tree from slot 151, as Base's and
/// Eden's do.
pub const TREE_SLOT: u64 = 151;
/// The QBFT validator set this image trusts.
pub const VALIDATORS: [Address; 1] = [pinned(
    option_env!("BESU_VALIDATOR"),
    address!("9ACe61fBa467570B3345Ee6ab8dBF9E0aE577969"),
)];

/// Item 12 of a block header is `extraData`.
const EXTRA_DATA: usize = 12;
/// A QBFT `extraData` list: vanity, validators, vote, round, seals.
const EXTRA_ITEMS: usize = 5;
const SEALS: usize = 4;
const ROUND: usize = 3;

/// The validator address an image pins: `built`, the build environment's, when set and not
/// empty, else `default`. Checked at compile time, so a malformed address fails the build.
const fn pinned(built: Option<&str>, default: Address) -> Address {
    match built {
        Some(addr) if !addr.is_empty() => {
            let bytes = addr.as_bytes();
            let bytes = match bytes {
                [b'0', b'x', rest @ ..] => rest,
                _ => bytes,
            };
            match hex::const_decode_to_array::<20>(bytes) {
                Ok(a) => Address::new(a),
                Err(_) => panic!("BESU_VALIDATOR in the build environment is a 20-byte address"),
            }
        }
        _ => default,
    }
}

pub struct Besu {
    pub validators: &'static [Address],
}

/// A block as `debug_getRawHeader` serves it: the header's RLP, seals included.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Input {
    pub header: Bytes,
}

/// What a sealed header says about its block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedBlock {
    pub state_root: B256,
    pub number: u64,
    pub timestamp: u64,
    /// The block hash as Besu reports it.
    pub hash: B256,
}

impl Origin for Besu {
    fn verify(&self, input: Value, trusted: &IsmState) -> anyhow::Result<Head> {
        let input: Input = origin::parse("besu input", input)?;
        let block = verify_block(&input.header, self.validators)?;
        anyhow::ensure!(
            block.number > trusted.height,
            "sealed block {} is not past the trusted height {}",
            block.number,
            trusted.height
        );
        Ok(Head {
            root: block.state_root,
            height: block.number,
            timestamp: block.timestamp,
            // No light-client store: the pinned validators are the whole of it.
            store_commit: trusted.lc_store_commit,
            attested_at: block.timestamp,
        })
    }

    fn merkle_tree(&self, proof: Value, root: B256) -> anyhow::Result<Tree> {
        crate::evm::read_tree(proof, root, TREE_SLOT)
    }
}

/// The quorum QBFT needs of `n` validators: `ceil(2n / 3)`, as Besu's `BftHelpers` has it.
pub fn quorum(n: usize) -> usize {
    (2 * n).div_ceil(3)
}

/// Check that a quorum of `validators` commit-sealed the header `rlp`, and read the block out
/// of it. The relayer uses this too, to offer only blocks the enclave will accept.
pub fn verify_block(rlp: &[u8], validators: &[Address]) -> anyhow::Result<SealedBlock> {
    let header = Parsed::new(rlp)?;
    let digest = keccak256(header.encode(false));
    let mut signed: Vec<Address> = Vec::new();
    for seal in header.seals()? {
        let signature =
            Signature::from_raw(seal).map_err(|e| anyhow::anyhow!("malformed commit seal: {e}"))?;
        let signer = signature
            .recover_address_from_prehash(&digest)
            .map_err(|e| anyhow::anyhow!("commit seal does not recover: {e}"))?;
        if validators.contains(&signer) && !signed.contains(&signer) {
            signed.push(signer);
        }
    }
    let needed = quorum(validators.len());
    anyhow::ensure!(
        signed.len() >= needed,
        "{} of the pinned validators sealed the block, {needed} needed",
        signed.len()
    );
    let fields = BlockHeader::decode(rlp)?;
    Ok(SealedBlock {
        state_root: fields.state_root,
        number: fields.number,
        timestamp: fields.timestamp,
        hash: keccak256(header.encode(true)),
    })
}

/// The hash Besu gives a QBFT block: its header without seals and with round zero. The relayer
/// checks a header it fetched against the RPC's hash with this; the enclave does not need it.
pub fn onchain_hash(rlp: &[u8]) -> anyhow::Result<B256> {
    Ok(keccak256(Parsed::new(rlp)?.encode(true)))
}

/// A header's raw RLP items, and its `extraData`'s.
struct Parsed<'a> {
    items: Vec<&'a [u8]>,
    extra: Vec<&'a [u8]>,
}

fn malformed() -> anyhow::Error {
    anyhow::anyhow!("QBFT block header RLP is malformed")
}

/// The raw items of an RLP list that is exactly `bytes`.
fn list_items(bytes: &[u8]) -> anyhow::Result<Vec<&[u8]>> {
    let mut slice = bytes;
    let alloy_rlp::PayloadView::List(items) =
        alloy_rlp::Header::decode_raw(&mut slice).map_err(|_| malformed())?
    else {
        return Err(malformed());
    };
    anyhow::ensure!(slice.is_empty(), malformed());
    Ok(items)
}

/// An RLP byte string's contents.
fn string(item: &[u8]) -> anyhow::Result<&[u8]> {
    let mut item = item;
    let out = alloy_rlp::Header::decode_bytes(&mut item, false).map_err(|_| malformed())?;
    anyhow::ensure!(item.is_empty(), malformed());
    Ok(out)
}

fn list_header(len: usize, out: &mut Vec<u8>) {
    alloy_rlp::Header {
        list: true,
        payload_length: len,
    }
    .encode(out);
}

impl<'a> Parsed<'a> {
    fn new(rlp: &'a [u8]) -> anyhow::Result<Self> {
        let items = list_items(rlp)?;
        anyhow::ensure!(items.len() > EXTRA_DATA + 2, malformed());
        let extra = list_items(string(items[EXTRA_DATA])?)?;
        anyhow::ensure!(
            extra.len() == EXTRA_ITEMS,
            "extraData is not QBFT's: {} items, not {EXTRA_ITEMS}",
            extra.len()
        );
        Ok(Self { items, extra })
    }

    /// The commit seals, 65 bytes each.
    fn seals(&self) -> anyhow::Result<Vec<&'a [u8]>> {
        let mut out = Vec::new();
        for seal in list_items(self.extra[SEALS])? {
            let seal = string(seal)?;
            anyhow::ensure!(seal.len() == 65, "a commit seal is 65 bytes");
            out.push(seal);
        }
        Ok(out)
    }

    /// The header re-encoded with no seals, and with round zero when `zero_round`.
    fn encode(&self, zero_round: bool) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let mut extra_payload = Vec::new();
        for (i, item) in self.extra.iter().enumerate() {
            match i {
                ROUND if zero_round => 0u64.encode(&mut extra_payload),
                SEALS => list_header(0, &mut extra_payload),
                _ => extra_payload.extend_from_slice(item),
            }
        }
        let mut extra = Vec::new();
        list_header(extra_payload.len(), &mut extra);
        extra.extend_from_slice(&extra_payload);

        let mut payload = Vec::new();
        for (i, item) in self.items.iter().enumerate() {
            if i == EXTRA_DATA {
                extra.as_slice().encode(&mut payload);
            } else {
                payload.extend_from_slice(item);
            }
        }
        let mut out = Vec::new();
        list_header(payload.len(), &mut out);
        out.extend_from_slice(&payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Block 5 of a single-validator QBFT devnet (Besu 26.11.0), as `eth_getBlockByNumber`
    /// reports it, sealed by the devnet's validator.
    fn fixture() -> (Vec<u8>, Value) {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/besu_qbft_block.json");
        let block: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rlp = hex::decode(block["rawHeader"].as_str().unwrap()).unwrap();
        (rlp, block)
    }

    #[test]
    fn a_sealed_block_verifies_and_hashes_as_besu_reports_it() {
        let (rlp, block) = fixture();
        let sealed = verify_block(&rlp, &VALIDATORS).unwrap();
        assert_eq!(
            sealed.hash,
            block["hash"].as_str().unwrap().parse::<B256>().unwrap()
        );
        assert_eq!(
            sealed.state_root,
            block["stateRoot"]
                .as_str()
                .unwrap()
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(sealed.number, 5);
        assert_eq!(onchain_hash(&rlp).unwrap(), sealed.hash);
    }

    #[test]
    fn another_validator_set_or_a_changed_header_is_refused() {
        let (rlp, block) = fixture();
        let stranger = address!("0000000000000000000000000000000000000001");
        assert!(verify_block(&rlp, &[stranger]).is_err());
        // One of two pinned validators is not a quorum.
        assert!(verify_block(&rlp, &[VALIDATORS[0], stranger]).is_err());
        // A header with another state root is not the one that was sealed.
        let root = hex::decode(block["stateRoot"].as_str().unwrap()).unwrap();
        let at = rlp.windows(32).position(|w| w == root.as_slice()).unwrap();
        let mut changed = rlp.clone();
        changed[at] ^= 1;
        assert!(verify_block(&changed, &VALIDATORS).is_err());
    }

    /// Block 5 of the same devnet with Prague and Osaka active from genesis (the return leg's
    /// P-256 precompile): the header gains `requestsHash`, and still verifies.
    #[test]
    fn an_osaka_block_verifies_too() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/besu_qbft_block_osaka.json"
        );
        let block: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(block["requestsHash"].is_string());
        let rlp = hex::decode(block["rawHeader"].as_str().unwrap()).unwrap();
        let sealed = verify_block(&rlp, &VALIDATORS).unwrap();
        assert_eq!(
            sealed.hash,
            block["hash"].as_str().unwrap().parse::<B256>().unwrap()
        );
        assert_eq!(sealed.number, 5);
        assert_eq!(onchain_hash(&rlp).unwrap(), sealed.hash);
    }

    #[test]
    fn quorum_is_two_thirds_rounded_up() {
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(3), 2);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(7), 5);
    }
}
