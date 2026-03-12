// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WithConstructor {
    uint64 public value;

    constructor() {
        value = 42;
    }

    function getValue() public returns (uint64) {
        return value;
    }
}
// ---- Expect: diagnostics ----
// error: 7:5-19: constructors are not supported on Antelope. Use an explicit init() action instead.
// warning: 11:5-48: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
