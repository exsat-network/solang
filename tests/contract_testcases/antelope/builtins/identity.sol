// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IdentityTest {
    uint64 public lastSelf;
    uint64 public lastCode;
    uint64 public lastTime;

    function checkIdentity() public {
        lastSelf = antelope.self();
        lastCode = antelope.code();
        lastTime = antelope.timestamp();
    }

    function nameTest() public returns (uint64) {
        return antelope.name("eosio.token");
    }
}
// ---- Expect: diagnostics ----
// warning: 15:5-48: function can be declared 'pure'
