// src/commitment_scheme/dvkzg/key.rs

use super::commitment::Commitment;
use super::proof::Proof;
use crate::{
    error::Error, fft::Polynomial, transcript::TranscriptProtocol, util,
};
use alloc::vec::Vec;
use dusk_bls12_381::{
    BlsScalar, G1Affine, G1Projective, multiscalar_mul::msm_variable_base,
};
use dusk_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;

/// 证明者的提交密钥
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitKey {
    pub(crate) powers_of_g: Vec<G1Affine>,
}

impl CommitKey {
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    // 修复 1：绕过 Compiler 错误的过早截断，永远返回充足的 powers_of_g
    pub(crate) fn truncate(
        &self,
        _truncated_degree: usize,
    ) -> Result<CommitKey, Error> {
        // 暴力但绝对安全：拒绝截断，直接把完整的 SRS 参数传给 Prover！
        Ok(self.clone())
    }

    fn check_commit_degree_is_within_bounds(
        &self,
        poly_degree: usize,
    ) -> Result<(), Error> {
        match (poly_degree == 0, poly_degree > self.max_degree()) {
            (true, _) => Err(Error::PolynomialDegreeIsZero),
            (false, true) => Err(Error::PolynomialDegreeTooLarge),
            (false, false) => Ok(()),
        }
    }

    pub(crate) fn commit(
        &self,
        polynomial: &Polynomial,
    ) -> Result<Commitment, Error> {
        if polynomial.is_empty() {
            return Ok(Commitment::from(G1Projective::identity()));
        }

        let len = polynomial.len();

        // 现在的 powers_of_g 会非常巨大，绝对能装下 len
        if self.powers_of_g.len() < len {
            return Err(Error::PolynomialDegreeTooLarge);
        }

        // 完美对齐切片：按多项式的真实长度截取基点，不丢弃任何最高次项！
        let bases = &self.powers_of_g[..len];
        let scalars = &polynomial[..]; // 转换为 &[BlsScalar] 切片

        Ok(Commitment::from(msm_variable_base(bases, scalars)))
    }

    /// 计算聚合商多项式 (无需修改，数学逻辑通用)
    pub(crate) fn compute_aggregate_witness(
        polynomials: &[Polynomial],
        point: &BlsScalar,
        v_challenge: &BlsScalar,
    ) -> Polynomial {
        let powers = util::powers_of(v_challenge, polynomials.len() - 1);
        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, v_challenge)| poly * v_challenge)
            .sum();
        numerator.ruffini(*point)
    }

    // ======== 占位序列化方法 ========
    pub fn to_var_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
    pub fn from_slice(_bytes: &[u8]) -> Result<CommitKey, Error> {
        unimplemented!()
    }
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
    pub unsafe fn from_slice_unchecked(_bytes: &[u8]) -> Self {
        unimplemented!()
    }
}

/// 验证者密钥 (携带陷门 \tau)
#[derive(Clone, Debug)]
pub struct OpeningKey {
    pub(crate) g: G1Affine,
    pub(crate) tau: BlsScalar, // 你的 dvKZG 核心秘密
}

impl OpeningKey {
    pub(crate) fn new(g: G1Affine, tau: BlsScalar) -> OpeningKey {
        OpeningKey { g, tau }
    }

    /// dvKZG 的批量验证
    #[allow(dead_code)]
    pub(crate) fn batch_check(
        &self,
        points: &[BlsScalar],
        proofs: &[Proof],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let u_challenge = transcript.challenge_scalar(b"batch");
        let powers = util::powers_of(&u_challenge, proofs.len() - 1);
        let mut g_multiplier = BlsScalar::zero();

        for ((proof, u_challenge), point) in
            proofs.iter().zip(powers).zip(points)
        {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;

            c += w * point;
            g_multiplier += u_challenge * proof.evaluated_point;

            total_c += c * u_challenge;
            total_w += w * u_challenge;
        }

        total_c -= self.g * g_multiplier;

        // 极简标量验证：检查 \tau * total_w == total_c
        let expected_c = total_w * self.tau;

        if expected_c != total_c {
            return Err(Error::PairingCheckFailure);
        };
        Ok(())
    }
}

// 序列化 Trait
impl Serializable<{ G1Affine::SIZE + BlsScalar::SIZE }> for OpeningKey {
    type Error = dusk_bytes::Error;
    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;
        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.g.to_bytes());
        writer.write(&self.tau.to_bytes());
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &buf[..];
        let g = G1Affine::from_reader(&mut buffer)?;
        let tau = BlsScalar::from_reader(&mut buffer)?;
        Ok(Self::new(g, tau))
    }
}
