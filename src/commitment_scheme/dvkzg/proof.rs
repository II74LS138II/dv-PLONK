// src/commitment_scheme/dvkzg/proof.rs

use super::commitment::Commitment;
use dusk_bls12_381::BlsScalar;

/// 证明一个多项式在点 z 处的求值为 y (即 evaluated_point)
/// 在 dvKZG 中，这个结构体是对 (C, y, Q) 的打包
#[derive(Copy, Clone, Debug)]
pub struct Proof {
    /// 核心证明：商多项式的承诺 Q = q(\tau)G
    pub(crate) commitment_to_witness: Commitment,
    /// 声明：求值 y
    pub(crate) evaluated_point: BlsScalar,
    /// 声明：原多项式的承诺 C = f(\tau)G
    pub(crate) commitment_to_polynomial: Commitment,
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::util::powers_of;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::G1Projective;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    /// 聚合证明：批量证明多个多项式在同一个点 z 的求值
    #[derive(Debug)]
    pub struct AggregateProof {
        /// 聚合后的商多项式承诺 (Q_agg)
        pub(crate) commitment_to_witness: Commitment,
        /// 各个多项式的求值点 (y_1, y_2, ...)
        pub(crate) evaluated_points: Vec<BlsScalar>,
        /// 各个原多项式的承诺 (C_1, C_2, ...)
        pub(crate) commitments_to_polynomials: Vec<Commitment>,
    }

    impl AggregateProof {
        /// 使用聚合商承诺初始化
        pub(crate) fn with_witness(witness: Commitment) -> AggregateProof {
            AggregateProof {
                commitment_to_witness: witness,
                evaluated_points: Vec::new(),
                commitments_to_polynomials: Vec::new(),
            }
        }

        /// 添加需要聚合的 (求值, 承诺) 对
        pub(crate) fn add_part(&mut self, part: (BlsScalar, Commitment)) {
            self.evaluated_points.push(part.0);
            self.commitments_to_polynomials.push(part.1);
        }

        /// 使用挑战因子 v，将 AggregateProof 拍平(Flatten)为一个单一的 Proof
        /// 这个线性同态叠加逻辑在 dvKZG 中同样完美适用！
        pub(crate) fn flatten(&self, v_challenge: &BlsScalar) -> Proof {
            let powers = powers_of(
                v_challenge,
                self.commitments_to_polynomials.len() - 1,
            );

            #[cfg(not(feature = "std"))]
            let flattened_poly_commitments_iter =
                self.commitments_to_polynomials.iter().zip(powers.iter());
            #[cfg(not(feature = "std"))]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.iter().zip(powers.iter());

            #[cfg(feature = "std")]
            let flattened_poly_commitments_iter = self
                .commitments_to_polynomials
                .par_iter()
                .zip(powers.par_iter());
            #[cfg(feature = "std")]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.par_iter().zip(powers.par_iter());

            // 聚合多项式承诺: C_agg = \sum v^i * C_i
            let flattened_poly_commitments: G1Projective =
                flattened_poly_commitments_iter
                    .map(|(poly, v_challenge)| poly.0 * v_challenge)
                    .sum();

            // 聚合求值: y_agg = \sum v^i * y_i
            let flattened_poly_evaluations: BlsScalar =
                flattened_poly_evaluations_iter
                    .map(|(eval, v_challenge)| eval * v_challenge)
                    .sum();

            Proof {
                commitment_to_witness: self.commitment_to_witness,
                evaluated_point: flattened_poly_evaluations,
                commitment_to_polynomial: Commitment::from(
                    flattened_poly_commitments,
                ),
            }
        }
    }
}
