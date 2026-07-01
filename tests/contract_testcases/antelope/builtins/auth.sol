// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuthTest {
    function doAuth(uint64 account) public {
        antelope.requireAuth(account);
    }

    function checkAuth(uint64 account) public returns (bool) {
        return antelope.hasAuth(account);
    }

    function doAuth2(uint64 account, uint64 permission) public {
        antelope.requireAuth2(account, permission);
    }
}
// ---- Expect: diagnostics ----
// warning: 5:5-43: function can be declared 'pure'
// warning: 9:5-61: function can be declared 'pure'
// warning: 13:5-63: function can be declared 'pure'
