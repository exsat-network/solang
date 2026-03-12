// SPDX-License-Identifier: Apache-2.0

use crate::{build_solidity, encode_action_data, ActionParam};

#[test]
fn event_with_multiple_fields() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            event Transfer(uint64 from, uint64 to, uint64 amount);

            function send(uint64 from, uint64 to, uint64 amount) public {
                emit Transfer(from, to, amount);
            }
        }
        "#,
    );

    let data = encode_action_data(&[
        ActionParam::U64(1),
        ActionParam::U64(2),
        ActionParam::U64(100),
    ]);
    vm.action("send", data);
    assert_eq!(vm.inline_actions().len(), 1, "should produce exactly one inline action");
}

#[test]
fn multiple_events_in_one_action() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            event Step(uint64 n);

            function multistep() public {
                emit Step(1);
                emit Step(2);
                emit Step(3);
            }
        }
        "#,
    );

    vm.action("multistep", vec![]);
    assert_eq!(vm.inline_actions().len(), 3, "should produce three inline actions");
}

#[test]
fn event_and_print_together() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            event Done(uint64 val);

            function work(uint64 v) public {
                print("working");
                emit Done(v);
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::U64(42)]);
    vm.action("work", data);
    assert_eq!(vm.prints(), "working");
    assert_eq!(vm.inline_actions().len(), 1);
}

#[test]
fn no_event_no_inline_action() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function noop() public {
                print("nothing");
            }
        }
        "#,
    );

    vm.action("noop", vec![]);
    assert!(vm.inline_actions().is_empty(), "no events means no inline actions");
}
