// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint64 public count;

    function increment() public {
        count += 1;
    }

    function reset() public {
        count = 0;
    }

    function getCount() public returns (uint64) {
        return count;
    }
}
// ---- Expect: diagnostics ----
// warning: 15:5-48: function can be declared 'view'
// warning: 15:5-48: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
