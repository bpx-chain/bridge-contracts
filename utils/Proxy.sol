// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

import "./Ownable.sol";

contract Proxy is Ownable {
    address implementation;
    
    constructor(address _implementation) {
        _init_Ownable(msg.sender);
        implementation = _implementation;
    }
    
    function setImplementation(address _implementation) external onlyOwner {
        implementation = _implementation;
    }
    
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(implementation.slot), 0, calldatasize(), 0, 0)
            
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}