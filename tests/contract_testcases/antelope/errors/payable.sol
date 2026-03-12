// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PayableTest {
    function deposit() public payable {
    }
}
// ---- Expect: diagnostics ----
// error: 5:5-38: Antelope does not support payable functions. Use explicit token transfer actions instead.
