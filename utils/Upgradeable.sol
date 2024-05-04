// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

import "./Ownable.sol";

abstract contract Upgradeable is Ownable {
    address implementation;
    uint256 private version;
       
    modifier initVer(uint256 _version) {
        require(
            version == 0,
            "Already initialized"
        );
        _;
        version = _version;
    }
    
    modifier upgradeVer(uint256 _version) {
        require(
            version == _version - 1,
            "Invalid current version"
        );
        _;
        version = _version;
    }
    
    modifier requireVer(uint256 _version) {
        require(
            version >= _version,
            "Invalid version"
        );
        _;
    }
}