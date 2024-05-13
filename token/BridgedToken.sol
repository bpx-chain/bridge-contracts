// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract BridgedToken is ERC20, ERC20Burnable, Ownable, ERC20Permit {
    uint8 _decimals;
    
    constructor(string memory name, string memory symbol, uint8 decimals, address bridge)
        ERC20(name, symbol)
        Ownable(bridge)
        ERC20Permit(name)
    {
        _decimals = decimals;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
    
    function decimals() public view override returns (uint8) {
		return _decimals;
	}
}
