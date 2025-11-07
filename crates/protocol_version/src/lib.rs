// NOTE: Usage of allow(dead_code) is intentional here, as fields are used in the Debug macro,
// but the compiler doesn't seem to be able to infer it directly.

/// Represents a specific protocol version supported by the prover, from prover's perspective.
#[derive(Debug)]
#[allow(dead_code)]
struct ProtocolVersion {
    /// verification key hash identifying this protocol version
    vk_hash: VerificationKeyHash,
    /// version of airbender used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    airbender_version: AirbenderVersion,
    /// version of zksync os used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zksync_os_version: ZkSyncOSVersion,
    /// version of zkos wrapper used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zkos_wrapper: ZkOsWrapperVersion,
    /// md5sum of the prover binary used for proving
    /// NOTE: in the future we may want to support multiple binaries (such as debug mode)
    /// NOTE2: this can be inferred from zksync_os_version, but we keep it here for easier cross-checking
    bin_md5sum: BinMd5Sum,
}

#[derive(Debug)]
struct VerificationKeyHash(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct AirbenderVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkSyncOSVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkOsWrapperVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct BinMd5Sum(&'static str);

/// Corresponds to server's execution_version 3 (or v1.1)
#[allow(dead_code)]
const V3: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x6a4509801ec284b8921c63dc6aaba668a0d71382d87ae4095ffc2235154e9fa3",
    ),
    airbender_version: AirbenderVersion("v0.5.0"),
    zksync_os_version: ZkSyncOSVersion("v0.0.26"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.0"),
    bin_md5sum: BinMd5Sum("fd9fd6ebfcfe7b3d1557e8a8b8563dd6"),
};

/// Corresponds to server's execution_version 4 (or v1.2)
const V4: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0xa385a997a63cc78e724451dca8b044b5ef29fcdc9d8b6ced33d9f58de531faa5",
    ),
    airbender_version: AirbenderVersion("v0.5.1"),
    zksync_os_version: ZkSyncOSVersion("v0.1.0"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.3"),
    bin_md5sum: BinMd5Sum("a3fffd4f2e14e7171c2207e470316e5f"),
};

/// Represents the set of supported protocol versions by this prover implementation.
#[derive(Debug)]
pub struct SupportedProtocolVersions {
    versions: Vec<ProtocolVersion>,
}

impl Default for SupportedProtocolVersions {
    fn default() -> Self {
        Self { versions: vec![V4] }
    }
}

impl SupportedProtocolVersions {
    /// Checks if the given VK hash is supported.
    pub fn contains(&self, vk_hash: &str) -> bool {
        self.versions.iter().any(|v| v.vk_hash.0 == vk_hash)
    }

    /// Returns the list of supported VK hashes as strings.
    pub fn vk_hashes(&self) -> Vec<String> {
        self.versions
            .iter()
            .map(|version| version.vk_hash.0.to_string())
            .collect()
    }
}
