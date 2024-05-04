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
        address target = implementation;
        require(target != address(0));
        
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let result := delegatecall(gas(), target, ptr, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
      
            switch result
            case 0 { revert(ptr, size) }
            default { return(ptr, size) }
        }
    }
}