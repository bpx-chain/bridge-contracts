// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

abstract contract Ownable {
    address private owner;
    
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Unauthorized"
        );
        _;
    }
    
    function _init_Ownable(address _owner) internal {
        owner = _owner;
    }
    
    function setOwner(address _owner) external onlyOwner {
        owner = _owner;
    }
}