// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CrossContract {
    function sendTransfer(uint64 from, uint64 to, int64 amount, string memory memo) public {
        bytes memory packed = antelope.pack(from, to, amount, antelope.name("EOS"), memo);
        antelope.call(antelope.name("eosio.token"), antelope.name("transfer"), packed);
    }

    function sendWithAuth(uint64 from, uint64 to, int64 amount, string memory memo) public {
        bytes memory packed = antelope.pack(from, to, amount, antelope.name("EOS"), memo);
        antelope.callauth(
            antelope.name("eosio.token"),
            antelope.name("transfer"),
            packed,
            from,
            antelope.name("active")
        );
    }

    function notify(uint64 account) public {
        antelope.requireRecipient(account);
    }
}
// ---- Expect: diagnostics ----
// warning: 5:5-91: function can be declared 'pure'
// warning: 10:5-91: function can be declared 'pure'
// warning: 21:5-43: function can be declared 'pure'
