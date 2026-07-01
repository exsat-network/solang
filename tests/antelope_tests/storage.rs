// SPDX-License-Identifier: Apache-2.0

use crate::{build_solidity, encode_action_data, string_to_name, ActionParam};

#[test]
fn mapping_store_and_load() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            mapping(uint64 => uint64) public data;

            function store(uint64 key, uint64 val) public {
                data[key] = val;
            }

            function check(uint64 key, uint64 expected) public {
                if (data[key] == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    // Store a value
    let data = encode_action_data(&[ActionParam::U64(1), ActionParam::U64(42)]);
    vm.action("store", data);

    // Read back the exact value
    let data = encode_action_data(&[ActionParam::U64(1), ActionParam::U64(42)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    // Wrong value should not match
    let data = encode_action_data(&[ActionParam::U64(1), ActionParam::U64(99)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "mismatch");

    // Non-existent key should read as 0
    let data = encode_action_data(&[ActionParam::U64(999), ActionParam::U64(0)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");
}

#[test]
fn storage_overwrite() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            uint64 public val;

            function setval(uint64 v) public {
                val = v;
            }

            function check(uint64 expected) public {
                if (val == expected) {
                    print("match");
                } else {
                    print("mismatch");
                }
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::U64(10)]);
    vm.action("setval", data);
    let rows_after_first: usize = vm.tables().values().map(|t| t.rows.len()).sum();

    // Verify value is 10
    let data = encode_action_data(&[ActionParam::U64(10)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    // Overwrite with 20
    let data = encode_action_data(&[ActionParam::U64(20)]);
    vm.action("setval", data);
    let rows_after_second: usize = vm.tables().values().map(|t| t.rows.len()).sum();

    // Row count shouldn't grow (update path, not insert)
    assert_eq!(rows_after_first, rows_after_second, "overwrite should not add rows");

    // Verify value is now 20, not 10
    let data = encode_action_data(&[ActionParam::U64(20)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "match");

    let data = encode_action_data(&[ActionParam::U64(10)]);
    vm.action("check", data);
    assert_eq!(vm.prints(), "mismatch");
}

#[test]
fn multiple_state_vars() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            uint64 public a;
            uint64 public b;

            function setboth(uint64 va, uint64 vb) public {
                a = va;
                b = vb;
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::U64(100), ActionParam::U64(200)]);
    vm.action("setboth", data);

    // Both variables stored — should have table rows
    let total_rows: usize = vm.tables().values().map(|t| t.rows.len()).sum();
    assert!(total_rows >= 2, "should have at least 2 storage rows for 2 variables");
}

#[test]
fn string_storage() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            string public stored;

            function save(string memory s) public {
                stored = s;
            }

            function read() public {
                print(stored);
            }
        }
        "#,
    );

    let data = encode_action_data(&[ActionParam::String("hello world".to_string())]);
    vm.action("save", data);

    // Read back the exact string
    vm.action("read", vec![]);
    assert_eq!(vm.prints(), "hello world");
}

#[test]
fn bool_storage() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            bool public flag;

            function setflag(bool v) public {
                flag = v;
            }

            function readflag() public {
                if (flag) {
                    print("true");
                } else {
                    print("false");
                }
            }
        }
        "#,
    );

    // Set true and read back
    let data = encode_action_data(&[ActionParam::Bool(true)]);
    vm.action("setflag", data);
    vm.action("readflag", vec![]);
    assert_eq!(vm.prints(), "true");

    // Set false and read back — verifies overwrite works for bools
    let data = encode_action_data(&[ActionParam::Bool(false)]);
    vm.action("setflag", data);
    vm.action("readflag", vec![]);
    assert_eq!(vm.prints(), "false");
}

#[test]
fn checked_arithmetic_overflow_reverts() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function add(uint64 a, uint64 b) public {
                uint64 c = a + b;
                // If we get here, no overflow
                if (c > 0) {
                    print("ok");
                }
            }
        }
        "#,
    );

    // Normal addition should succeed
    let data = encode_action_data(&[ActionParam::U64(10), ActionParam::U64(20)]);
    vm.action("add", data);
    assert_eq!(vm.prints(), "ok");

    // Overflow: max_uint64 + 1 should revert
    let data = encode_action_data(&[ActionParam::U64(u64::MAX), ActionParam::U64(1)]);
    vm.action_expect_failure("add", data);
}

#[test]
fn checked_arithmetic_underflow_reverts() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            function sub(uint64 a, uint64 b) public {
                uint64 c = a - b;
                if (c == 0) {
                    print("zero");
                } else {
                    print("nonzero");
                }
            }
        }
        "#,
    );

    // Normal subtraction
    let data = encode_action_data(&[ActionParam::U64(10), ActionParam::U64(10)]);
    vm.action("sub", data);
    assert_eq!(vm.prints(), "zero");

    // Underflow: 5 - 10 should revert
    let data = encode_action_data(&[ActionParam::U64(5), ActionParam::U64(10)]);
    vm.action_expect_failure("sub", data);
}

#[test]
fn delete_mapping_entry() {
    let mut vm = build_solidity(
        r#"
        contract Test {
            mapping(uint64 => uint64) public data;

            function store(uint64 key, uint64 val) public {
                data[key] = val;
            }

            function remove(uint64 key) public {
                delete data[key];
            }

            function load(uint64 key) public {
                if (data[key] != 0) {
                    print("found");
                } else {
                    print("empty");
                }
            }
        }
        "#,
    );

    // Store a value
    let data = encode_action_data(&[ActionParam::U64(1), ActionParam::U64(42)]);
    vm.action("store", data);

    // Verify it's there
    let data = encode_action_data(&[ActionParam::U64(1)]);
    vm.action("load", data);
    assert_eq!(vm.prints(), "found");

    // Delete it
    let data = encode_action_data(&[ActionParam::U64(1)]);
    vm.action("remove", data);

    // Verify it's gone
    let data = encode_action_data(&[ActionParam::U64(1)]);
    vm.action("load", data);
    assert_eq!(vm.prints(), "empty");
}
