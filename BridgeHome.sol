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
    
    function initialize(uint _relayerStake, address[] calldata _trustedRelayers) external initVer(1) onlyOwner {
        _init_Bridge(_relayerStake, _trustedRelayers);
    }
    
    function isValidChainId(uint chainId) internal view override returns(bool) {
        return assetsDb[chainId].valid;
    }
    
    function _assetResolve(uint chainId, address contractLocal) internal view override returns(address) {
        require(
            assetsDb[chainId].assets[contractLocal].valid,
            "Asset not found"
        );
        return assetsDb[chainId].assets[contractLocal].contractRemote;
    }
    
    function chainUpdate(uint chainId, bool valid) external requireVer(1) onlyOwner {
        assetsDb[chainId].valid = valid;
    }
    
    function assetAdd(uint chainId, address contractLocal, address contractRemote) external requireVer(1) onlyOwner {
        assetsDb[chainId].assets[contractLocal].valid = true;
        assetsDb[chainId].assets[contractLocal].contractRemote = contractRemote;
    }
    
    function assetRemove(uint chainId, address contractLocal) external requireVer(1) onlyOwner {
        assetsDb[chainId].assets[contractLocal].valid = false;
    }
}