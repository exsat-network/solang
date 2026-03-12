// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Hello {
    function hi() public {
        print("Hello, Antelope!");
    }
}
// ---- Expect: diagnostics ----
// warning: 5:5-25: function can be declared 'pure'
