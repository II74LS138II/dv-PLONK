// src/commitment_scheme/dvkzg/srs.rs

use crate::{
    commitment_scheme::dvkzg::key::{CommitKey, OpeningKey},
    error::Error,
};
use alloc::vec::Vec;
use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

/// Deterministic dvKZG 的公共参数
#[derive(Debug, Clone)]
pub struct PublicParameters {
    /// 证明者用来生成承诺的密钥 (包含 G1 幂次)
    pub(crate) commit_key: CommitKey,
    /// 验证者用来验证的密钥 (你的方案中，这里面将藏着陷门 \tau)
    pub(crate) opening_key: OpeningKey,
}

impl PublicParameters {
    /// 由于你的方案去除了盲化因子，这里设为 0。
    /// (如果后续电路编译报错多项式度数不够，可以改回 6)
    const ADDED_BLINDING_DEGREE: usize = 0;

    /// 生成包含 \tau 陷门的全局公共参数
    pub fn setup<R: RngCore + CryptoRng>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<PublicParameters, crate::error::Error> {
        // 1. 生成决定整个宇宙命运的核心秘密: \tau
        let tau = BlsScalar::random(&mut *rng);

        // 2. 获取椭圆曲线 G1 的基础生成元 G
        let g = G1Affine::generator();

        // 3. 计算多项式承诺所需的 G, \tau G, \tau^2 G ...
        let mut powers_of_g = alloc::vec::Vec::with_capacity(max_degree + 1);
        let mut current_g = G1Projective::from(g);

        for _ in 0..=max_degree {
            powers_of_g.push(G1Affine::from(current_g));
            current_g *= tau; // 每次乘以 \tau 抬升一阶
        }

        // 4. 将生成的 \tau 结构分发给 Prover 和 Verifier
        let commit_key = CommitKey { powers_of_g };
        let opening_key = OpeningKey::new(g, tau); // Verifier 拿到最纯正的 \tau

        Ok(PublicParameters {
            commit_key,
            opening_key,
        })
    }

    /// 截断参数，PLONK 核心调用此方法来获取所需大小的密钥
    pub(crate) fn trim(
        &self,
        truncated_degree: usize,
    ) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_prover_key = self
            .commit_key
            .truncate(truncated_degree + Self::ADDED_BLINDING_DEGREE)?;
        let opening_key = self.opening_key.clone();
        Ok((truncated_prover_key, opening_key))
    }

    /// Max degree specifies the largest polynomial
    /// that this prover key can commit to.
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }

    // ==========================================================
    // 序列化与反序列化方法
    // 实际工程中，包含 \tau 的 PublicParameters 不应该被轻易公开序列化！
    // ==========================================================

    /// Serializes a [`PublicParameters`] struct into a slice of bytes.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        unimplemented!("dvKZG 参数不应轻易公开序列化")
    }

    /// Deserialize a slice of bytes into a Public Parameter struct.
    pub fn from_slice(_bytes: &[u8]) -> Result<PublicParameters, Error> {
        unimplemented!("dvKZG 参数不支持从公开切片反序列化")
    }

    /// Serialize the [`PublicParameters`] into bytes.
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        unimplemented!("dvKZG 参数不应轻易公开序列化")
    }

    /// Deserialize [`PublicParameters`] from a trusted set of bytes.
    ///
    /// # Safety
    /// This function does not perform any security checks.
    pub unsafe fn from_slice_unchecked(_bytes: &[u8]) -> Self {
        unimplemented!("dvKZG 参数不支持无检查反序列化")
    }
}
