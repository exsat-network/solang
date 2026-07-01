// SPDX-License-Identifier: Apache-2.0

use crate::{build_solidity, encode_action_data, string_to_name, ActionParam};

#[test]
fn hello_world() {
    let mut vm = build_solidity(
        r#"
        contract Hello {
            function hi() public {
                print("Hello, Antelope!");
            }
        }
        "#,
    );

    vm.action("hi", vec![]);
    assert_eq!(vm.prints(), "Hello, Antelope!");
}

#[test]
fn counter_increment() {
    let mut vm = build_solidity(
        r#"
        contract Counter {
            uint64 count;

            function increment() public {
                count += 1;
            }

            function check(uint64 expected) public {
                if (count == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    vm.action("increment", vec![]);
    let data = encode_action_data(&[ActionParam::U64(1)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    vm.action("increment", vec![]);
    vm.action("increment", vec![]);
    let data = encode_action_data(&[ActionParam::U64(3)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    // Verify wrong value doesn't match
    let data = encode_action_data(&[ActionParam::U64(99)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn string_param() {
    let mut vm = build_solidity(
        r#"
        contract Greeter {
            function greet(string memory who) public {
                print(who);
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::String("Alice".to_string())]);
    vm.action("greet", data);
    assert_eq!(vm.prints(), "Alice");
}

#[test]
fn uint64_param() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            uint64 public stored;

            function setval(uint64 val) public {
                stored = val;
            }

            function check(uint64 expected) public {
                if (stored == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::U64(42)]);
    vm.action("setval", data);

    let data = encode_action_data(&[ActionParam::U64(42)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    let data = encode_action_data(&[ActionParam::U64(99)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn require_auth_pass() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function authme(uint64 account) public {
                antelope.requireAuth(account);
                print("authorized");
            }
        }
        "#,
    );

    let receiver = string_to_name("testaccount");
    vm.set_auth(vec![receiver]);
    let data = encode_action_data(&[ActionParam::U64(receiver)]);
    vm.action("authme", data);
    assert_eq!(vm.prints(), "authorized");
}

#[test]
fn require_auth_fail() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function authme(uint64 account) public {
                antelope.requireAuth(account);
            }
        }
        "#,
    );

    let alice = string_to_name("alice");
    let receiver = string_to_name("testaccount");
    vm.set_auth(vec![receiver]);
    let data = encode_action_data(&[ActionParam::U64(alice)]);
    vm.action_expect_failure("authme", data);
}

#[test]
fn has_auth_check() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function check(uint64 account) public {
                if (antelope.hasAuth(account)) {
                    print("yes");
                } else {
                    print("no");
                }
            }
        }
        "#,
    );

    let receiver = string_to_name("testaccount");
    let alice = string_to_name("alice");
    vm.set_auth(vec![receiver]);

    let data = encode_action_data(&[ActionParam::U64(receiver)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "yes");

    let data = encode_action_data(&[ActionParam::U64(alice)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "no");
}

#[test]
fn emit_event_sends_inline_action() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            event Ping(uint64 value);

            function doping(uint64 val) public {
                emit Ping(val);
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::U64(123)]);
    vm.action("doping", data);
    assert!(
        !vm.inline_actions().is_empty(),
        "event should produce an inline action"
    );
}
