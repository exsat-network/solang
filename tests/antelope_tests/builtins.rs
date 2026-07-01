// SPDX-License-Identifier: Apache-2.0

use crate::{build_solidity, encode_action_data, string_to_name, ActionParam};

#[test]
fn self_returns_receiver() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function whoami(uint64 expected) public {
                uint64 me = antelope.self();
                if (me == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    let receiver = string_to_name("testaccount");
    let data = encode_action_data(&[ActionParam::U64(receiver)]);
    vm.action("whoami", data);
    assert_eq!(vm.prints(), "match");

    // Wrong value should not match
    let wrong = string_to_name("alice");
    let data = encode_action_data(&[ActionParam::U64(wrong)]);
    vm.action("whoami", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn timestamp_returns_value() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function checktime(uint64 expected) public {
                uint64 t = antelope.timestamp();
                if (t == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    // Mock returns 1704067200_000_000 (2024-01-01T00:00:00Z in microseconds)
    let data = encode_action_data(&[ActionParam::U64(1704067200_000_000)]);
    vm.action("checktime", data);
    assert_eq!(vm.prints(), "match");

    // Wrong value should not match
    let data = encode_action_data(&[ActionParam::U64(0)]);
    vm.action("checktime", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn require_auth2_pass() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function check(uint64 account, uint64 perm) public {
                antelope.requireAuth2(account, perm);
                print("ok");
            }
        }
        "#,
    );

    let receiver = string_to_name("testaccount");
    let active = string_to_name("active");
    vm.set_auth(vec![receiver]);
    let data = encode_action_data(&[ActionParam::U64(receiver), ActionParam::U64(active)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "ok");
}

#[test]
fn require_auth2_fail() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function check(uint64 account, uint64 perm) public {
                antelope.requireAuth2(account, perm);
            }
        }
        "#,
    );

    let alice = string_to_name("alice");
    let active = string_to_name("active");
    let receiver = string_to_name("testaccount");
    vm.set_auth(vec![receiver]);
    let data = encode_action_data(&[ActionParam::U64(alice), ActionParam::U64(active)]);
    vm.action_expect_failure("check", data);
}

#[test]
fn multiple_actions_independent_prints() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function alpha() public {
                print("a");
            }
            function beta() public {
                print("b");
            }
        }
        "#,
    );

    vm.action("alpha", vec![]);
    assert_eq!(vm.prints(), "a");

    vm.action("beta", vec![]);
    assert_eq!(vm.prints(), "b", "prints should be cleared between actions");
}

#[test]
fn name_builtin_compile_time() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function checkname(uint64 expected) public {
                uint64 alice = antelope.name("alice");
                if (alice == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    // antelope.name("alice") should equal string_to_name("alice")
    let alice = string_to_name("alice");
    let data = encode_action_data(&[ActionParam::U64(alice)]);
    vm.action("checkname", data);
    assert_eq!(vm.prints(), "match");

    // Wrong value should not match
    let data = encode_action_data(&[ActionParam::U64(0)]);
    vm.action("checkname", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn code_returns_code_param() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function checkcode(uint64 expected) public {
                uint64 c = antelope.code();
                if (c == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    // Direct call: code == receiver
    let receiver = string_to_name("testaccount");
    let data = encode_action_data(&[ActionParam::U64(receiver)]);
    vm.action("checkcode", data);
    assert_eq!(vm.prints(), "match");
}

#[test]
fn notification_dispatches_with_different_code() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function transfer() public {
                uint64 me = antelope.self();
                uint64 c = antelope.code();
                if (me != c) {
                    print("notification");
                } else {
                    print("direct");
                }
            }
        }
        "#,
    );

    // Direct call: code == receiver
    vm.action("transfer", vec![]);
    assert_eq!(vm.prints(), "direct");

    // Notification: code != receiver
    let eosio_token = string_to_name("eosio.token");
    vm.notification(eosio_token, "transfer", vec![]);
    assert_eq!(vm.prints(), "notification");
}
