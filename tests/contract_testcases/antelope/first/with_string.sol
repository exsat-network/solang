// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WithString {
    string public name;

    function setName(string memory newName) public {
        name = newName;
    }

    function greet(string memory who) public {
        print(who);
    }
}
// ---- Expect: diagnostics ----
// warning: 11:5-45: function can be declared 'pure'
