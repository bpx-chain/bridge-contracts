// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

import "./Bridge.sol";

contract BridgeHome is Bridge {
    struct DbChain {
        bool valid;
        mapping(address => DbAsset) assets;
    }
    
    struct DbAsset {
        bool valid;
        address contractRemote;
    }
    
    mapping(uint => DbChain) assetsDb;
    
    function initialize(uint _relayerStake, address[] calldata _trustedRelayers) external onlyOwner initVer(1) {
        _init_Bridge(_relayerStake, _trustedRelayers);
    }
    
    function isValidChainId(uint chainId) internal view override returns(bool) {
        return assetsDb[chainId].valid;
    }
    
    function _resolveAsset(uint chainId, address contractLocal) internal view override returns(address) {
        require(
            assetsDb[chainId].assets[contractLocal].valid,
            "Asset not found"
        );
        return assetsDb[chainId].assets[contractLocal].contractRemote;
    }
    
    function updateChain(uint chainId, bool valid) external onlyOwner {
        assetsDb[chainId].valid = valid;
    }
    
    function addAsset(uint chainId, address contractLocal, address contractRemote) external onlyOwner {
        assetsDb[chainId].assets[contractLocal].valid = true;
        assetsDb[chainId].assets[contractLocal].contractRemote = contractRemote;
    }
    
    function removeAsset(uint chainId, address contractLocal) external onlyOwner {
        assetsDb[chainId].assets[contractLocal].valid = false;
    }
}