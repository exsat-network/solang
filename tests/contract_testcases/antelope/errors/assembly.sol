// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AssemblyTest {
    function doAsm() public {
        assembly {
            let x := 1
        }
    }
}
// ---- Expect: diagnostics ----
// error: 6:9-8:10: inline assembly is not supported on Antelope. Use antelope.* builtins instead.
