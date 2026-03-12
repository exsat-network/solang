// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NestedMapping {
    mapping(address => mapping(address => uint256)) public allowances;

    function approve(address owner, address spender, uint256 amount) public {
        allowances[owner][spender] = amount;
    }

    function getAllowance(address owner, address spender) public returns (uint256) {
        return allowances[owner][spender];
    }
}
// ---- Expect: diagnostics ----
// warning: 11:5-83: function can be declared 'view'
// warning: 11:5-83: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
