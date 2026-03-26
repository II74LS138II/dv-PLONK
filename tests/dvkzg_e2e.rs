// tests/dvkzg_e2e.rs

use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;
use rand_core::OsRng;
// 引入原例中用到的 JubJub 曲线相关类型
use dusk_jubjub::{JubJubAffine, JubJubScalar};

#[derive(Debug, Default)]
pub struct TestCircuit {
    pub a: BlsScalar,
    pub b: BlsScalar,
    pub c: BlsScalar,
    pub d: BlsScalar,
    pub e: JubJubScalar,
    pub f: JubJubAffine,
}

impl Circuit for TestCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_witness(self.a);
        let b = composer.append_witness(self.b);
        let d = composer.append_witness(self.d);

        // 1) a < 2^6
        composer.component_range::<3>(a);
        // 2) b < 2^4
        composer.component_range::<2>(b);

        // 3) a + b + 42 = c where c is public input
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(a)
            .b(b)
            .constant(BlsScalar::from(42));
        let result = composer.gate_add(constraint);
        let c = composer.append_public(self.c);
        composer.assert_equal(result, c);

        // 4) a * b + d = 42
        let constraint = Constraint::new().mult(1).a(a).b(b).fourth(1).d(d);
        let result = composer.gate_mul(constraint);
        composer.assert_equal_constant(result, BlsScalar::from(42), None);

        // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a Public Input
        let e = composer.append_witness(self.e);
        let scalar_mul_result = composer
            .component_mul_generator(e, dusk_jubjub::GENERATOR_EXTENDED)?;
        composer.assert_equal_public_point(scalar_mul_result, self.f);

        Ok(())
    }
}

#[test]
fn test_dvkzg_plonk_pipeline() {
    let mut rng = OsRng;

    // ==========================================================
    // 阶段 1: Setup (使用官方例子的 1 << 12，即 4096)
    // ==========================================================
    println!("开始 Setup...");
    let label = b"dvkzg_test_circuit";
    let pp =
        PublicParameters::setup(1 << 14, &mut rng).expect("dvKZG Setup 失败");

    // ==========================================================
    // 阶段 2: 编译电路
    // ==========================================================
    println!("开始编译电路...");
    let (prover, verifier) =
        Compiler::compile::<TestCircuit>(&pp, label).expect("电路编译失败");

    // ==========================================================
    // 阶段 3: 实例化具体的真实输入，并生成证明
    // ==========================================================
    println!("Prover 正在生成确定性 dvKZG 证明...");
    let a = BlsScalar::from(31);
    let b = BlsScalar::zero();
    let c = BlsScalar::from(73);
    let d = BlsScalar::from(42);
    let e = JubJubScalar::one();
    let f: JubJubAffine = dusk_jubjub::GENERATOR_EXTENDED.into();

    // 生成带数据的真实电路实例
    let circuit = TestCircuit { a, b, c, d, e, f };
    let public_inputs = vec![c, f.get_u(), f.get_v()];

    let (proof, pi) = prover.prove(&mut rng, &circuit).expect("证明生成失败");

    // 确保提取出的公共输入是正确的
    assert_eq!(public_inputs, pi);

    // ==========================================================
    // 阶段 4: 证明验证 (Verifier)
    // ==========================================================
    println!("Verifier 正在验证...");
    let verify_result = verifier.verify(&proof, &public_inputs);

    assert!(
        verify_result.is_ok(),
        "dvKZG 证明验证失败！错误信息: {:?}",
        verify_result.err()
    );

    println!("🎉 恭喜！官方大型电路基于 Deterministic dvKZG 测试完美通过！");
}
