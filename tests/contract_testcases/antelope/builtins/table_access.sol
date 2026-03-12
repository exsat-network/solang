// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TableAccessTest {
    function readBalance(uint64 account, uint64 symbolCode) public returns (int64) {
        int32 iter = antelope.dbFind(
            antelope.name("eosio.token"),
            account,
            antelope.name("accounts"),
            symbolCode
        );
        if (iter < 0) return 0;
        bytes memory row = antelope.dbGet(iter);
        return antelope.toInt64(row, 0);
    }

    function countRows(uint64 code, uint64 scope, uint64 table) public returns (uint64) {
        uint64 count = 0;
        int32 iter = antelope.dbLowerbound(code, scope, table, 0);
        while (iter >= 0) {
            count += 1;
            iter = antelope.dbNext(iter);
        }
        return count;
    }

    function findByIdx64(uint64 code, uint64 scope, uint64 table, uint64 indexNum, uint64 key) public returns (uint64) {
        int32 secIter = antelope.dbIdx64Find(code, scope, table, indexNum, key);
        if (secIter < 0) return 0;
        return antelope.lastPk();
    }

    function decodeRow(bytes memory data) public pure returns (uint64, uint32, string memory) {
        uint64 val64 = antelope.toUint64(data, 0);
        uint32 val32 = antelope.toUint32(data, 8);
        string memory s = antelope.toString(data, 12);
        return (val64, val32, s);
    }
}
// ---- Expect: diagnostics ----
// warning: 5:5-83: function can be declared 'pure'
// warning: 5:5-83: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
// warning: 17:5-88: function can be declared 'pure'
// warning: 17:5-88: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
// warning: 27:5-119: function can be declared 'pure'
// warning: 27:5-119: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
// warning: 33:5-94: return values on public functions are ignored on Antelope. Use state variables or events to communicate results.
