// The data root start byte number from the end.
// E.g. data root byte start idx is N - DATA_ROOT_OFFSET_FROM_END where N is the header size.
pub const DATA_ROOT_OFFSET_FROM_END: u32 = 32;

// Number of headers processed per map job for subchain_verification map reduce.
pub const HEADERS_PER_MAP: usize = 8;

// Digest byte size.
pub const HASH_SIZE: usize = 32;

// Length of an Avail validator (pubkey + weight).
pub const VALIDATOR_LENGTH: usize = PUBKEY_LENGTH + WEIGHT_LENGTH;

// Length of an Avail pubkey.
pub const PUBKEY_LENGTH: usize = 32;

// Length of the weight of an Avail validator.
pub const WEIGHT_LENGTH: usize = 8;

// Length of the delay in an Avail header.
pub const DELAY_LENGTH: usize = 4;

// Length of the justification encoded precommit message.  This is what is
// signed by the authorities.
// Link: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/src/api_dev.rs#L30549-L30557.
pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

// Max number of authorities this circuit currently supports.
pub const MAX_AUTHORITY_SET_SIZE: usize = 300;
