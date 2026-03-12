// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20 {
    string public name;
    string public symbol;
    uint256 public totalSupply;
    uint64 public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function init(string memory _name, string memory _symbol, uint64 _owner) public {
        antelope.requireAuth(_owner);
        name = _name;
        symbol = _symbol;
        owner = _owner;
    }

    function mint(uint64 actor, address to, uint256 amount) public {
        antelope.requireAuth(actor);
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(uint64 actor, address from, address to, uint256 amount) public {
        antelope.requireAuth(actor);
        require(balanceOf[from] >= amount, "insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    function approve(uint64 actor, address _owner, address spender, uint256 amount) public {
        antelope.requireAuth(actor);
        allowance[_owner][spender] = amount;
        emit Approval(_owner, spender, amount);
    }
}
// ---- Expect: diagnostics ----
