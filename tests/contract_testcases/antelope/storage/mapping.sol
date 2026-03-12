// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MappingTest {
    mapping(uint64 => uint256) public balances;

    function set(uint64 key, uint256 value) public {
        balances[key] = value;
    }

    function get(uint64 key) public returns (uint256) {
        return balances[key];
    }

    function remove(uint64 key) public {
        delete balances[key];
    }
}
// ---- Expect: diagnostics ----
// warning: 11:5-54: function can be declared 'view'
// warning: 11:5-54: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
