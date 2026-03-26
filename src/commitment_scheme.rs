// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Ideally we should cleanly abstract away the polynomial commitment scheme
//! We note that PLONK makes use of the linearization technique
//! conceived in SONIC [Mary Maller].
//!
//! This technique implicitly requires the
//! commitment scheme to be homomorphic. `Merkle Tree like` techniques such as
//! FRI are not homomorphic and therefore for PLONK to be usable with all
//! commitment schemes without modification, one would need to remove the
//! linearizer

mod dvkzg;

// 1. 导出底层承诺点
pub(crate) use crate::commitment_scheme::dvkzg::commitment::Commitment;

// 2. 导出需要在堆上分配内存的组件 (密钥、参数和聚合证明)
#[cfg(feature = "alloc")]
pub(crate) use crate::commitment_scheme::dvkzg::proof::alloc::AggregateProof;

pub(crate) use crate::commitment_scheme::dvkzg::key::CommitKey;
pub(crate) use crate::commitment_scheme::dvkzg::key::OpeningKey;

#[cfg(feature = "alloc")]
pub use crate::commitment_scheme::dvkzg::srs::PublicParameters;

// 3. 序列化宏我们暂时保持注释状态，方便开发调试
// #[cfg(all(feature = "alloc", feature = "rkyv-impl"))]
// pub use dvkzg::{
//     ArchivedCommitKey, ArchivedOpeningKey, ArchivedPublicParameters,
//     CommitKeyResolver, OpeningKeyResolver, PublicParametersResolver,
// };
