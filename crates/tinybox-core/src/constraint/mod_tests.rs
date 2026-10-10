//! Hard requirements never accept partial enforcement.
use super::*;
#[test]
fn every_constraint_refuses_unsupported_and_best_effort() {
    for constraint in Constraint::ALL {
        for enforcement in [
            Enforcement::Unsupported,
            Enforcement::BestEffort,
            Enforcement::Enforced,
        ] {
            let support = ConstraintSupport::NONE.with(constraint, enforcement);
            assert_eq!(
                support.plan_check(&[constraint]).constraints,
                [(constraint, enforcement)]
            );
            let result = support.require("backend", &[constraint]);
            if enforcement == Enforcement::Enforced {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.err(),
                    Some(crate::Error::ConstraintNotEnforced {
                        sandbox: "backend".into(),
                        constraint,
                        enforcement
                    })
                );
            }
        }
    }
    assert_eq!(ConstraintSupport::default(), ConstraintSupport::NONE);
    assert!(ConstraintSupport::NONE.require("backend", &[]).is_ok());
}
