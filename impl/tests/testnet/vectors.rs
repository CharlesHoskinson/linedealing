//! Published and chain-derived test vectors. Sources are named per item.
#![allow(dead_code)]

/// BIP350 "Test vectors for v0-v16 native segregated witness addresses" (valid).
pub const SEGWIT_VALID: &[(&str, &str, &str)] = &[
    (
        "bc",
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    (
        "tb",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "bc",
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("bc", "BC1SW50QGDZ25J", "6002751e"),
    (
        "bc",
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "5210751e76e8199196d454941c45d1b3a323",
    ),
    (
        "tb",
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "tb",
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "bc",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
];
/// BIP350 invalid segwit addresses, with the HRP each is checked against.
pub const SEGWIT_INVALID: &[(&str, &str)] = &[
    (
        "bc",
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    ),
    (
        "bc",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    ),
    (
        "tb",
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    ),
    (
        "bc",
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    ),
    ("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"),
    (
        "tb",
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    ),
    (
        "bc",
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    ),
    (
        "bc",
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    ),
    ("bc", "bc1pw5dgrnzv"),
    (
        "bc",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    ),
    ("bc", "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"),
    (
        "tb",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    ),
    (
        "bc",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    ),
    (
        "tb",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    ),
    ("bc", "bc1gmk9yu"),
];
/// BIP86 "Account 0, first receiving address = m/86'/0'/0'/0/0".
pub const BIP86_INTERNAL: &str = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
pub const BIP86_OUTPUT: &str = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";
pub const BIP86_ADDRESS: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

/// EIP-55 "Test Cases" (all-mixed-case group).
pub const EIP55: &[&str] = &[
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
];

/// A confirmed Sepolia EIP-1559 value transfer (block 0xb94eef), read with
/// eth_getTransactionByHash and eth_getRawTransactionByHash on 2026-11-15.
pub mod sepolia {
    pub const HASH: &str = "a7dc72183a200c58ccb4a32dcc58a4c189c05b1c99548320c5b52eb4fbd773d0";
    pub const FROM: &str = "2fb4bea14df44957ebfa8ccc4b42ae50d5390e8f";
    pub const TO: &str = "55b4418b6512c4465fdcb8f3bbff45ffea77a1fd";
    pub const NONCE: u64 = 0x1c21;
    pub const VALUE: u128 = 0xb1a2bab9b72e78;
    pub const GAS: u64 = 0x5fe4;
    pub const MAX_FEE: u128 = 0x13;
    pub const MAX_PRIORITY: u128 = 0x2;
    pub const Y_PARITY: bool = false;
    pub const R: &str = "6007fa587f89a0d6101afa90bccaea9e9560d649f25b244b5ed4d4a4c9e3c01a";
    pub const S: &str = "02e0b38029d420ed47f168d9807bc64be9bad626ff47122b7940827486b3f032";
    pub const RAW: &str = "02f86e83aa36a7821c210213825fe49455b4418b6512c4465fdcb8f3bbff45ffea77a1fd87b1a2bab9b72e7880c080a06007fa587f89a0d6101afa90bccaea9e9560d649f25b244b5ed4d4a4c9e3c01aa002e0b38029d420ed47f168d9807bc64be9bad626ff47122b7940827486b3f032";
}

/// CIP-19 test vectors: payment key and its type-6 testnet address.
pub const CIP19_ADDR_VK: &str =
    "addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd";
pub const CIP19_TYPE6_TESTNET: &str =
    "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz";

/// A confirmed preprod transaction with one vkey witness, read with Koios
/// /tx_cbor on 2026-11-15.
pub mod preprod {
    pub const TX_HASH: &str = "61ed6bc05bfacb614b57e885d59e2f88cde350deefe377889d71464fbae607d2";
    pub const CBOR: &str = "84a40082825820ca6faf54363c0b90fcb08d7ab13a0c241f87951a4b5cd0382b4fd088abf99fb601825820da2ccc33e00193817f7c49162ac09ef9379d7e6c261cafbd20f533cd576bfe94010182a20058390010df27e611d5276a925399a353e5c3a9bdc0a494e74723e34655b4b0388a1d79fd0454ae4a10483d498ce5d842634b6cd67b078913b62885011a00181be0a2005839005a0768cf4bf8c8fc1f1a4dc8f42b1e4805aefdf0e44212f970aab1cd297b976357be9ebf6c11ad104f7300482c050d69b301e49934812b2401821a01d15e6da5581c54f9290a88a407b2a1b9ce2c9a96142d02a8d0b686a634346a00d1efa1485349524955532d421b000000037e11d600581c59e35b701247154f645388c5e17a098fced0e5098543dd58a797c04aa145524947454c1b00000002cb417800581c644825fe5f46cdedbbb14f26ef696bbd5a65b9875f8a17ce4ba445a7a1536772764c50284144412c5349524955532d41291a0071e202581c73dead11ca9e387fef50a8a68726a68273d607eea0f1d2bde205140fa1485349524955532d411b000000037e11d600581cc0e65618da9d3d39d20d0f7cdefc6481aebe616fe063a447d8647c90a144564547411b0000000165a0bc00021a0002c2210f00a100818258202bd3c9ccc0a4ca717c4df5355dfbc25d93e3bc332920577623bce793900921a458407e65341a915803d910ddc26288b3ac03ddf189a1a4cc6362f4443113414daeadbe866675884a8251b67d7b30e2205abbb4c825b5318d4dee676722778c66f008f5f6";
}
