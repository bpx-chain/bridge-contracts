// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

import "./Bridge.sol";

contract BridgeForeign is Bridge {
    uint private homeChainId;
    
    function initialize(uint _relayerStake, address[] calldata _trustedRelayers, uint _homeChainId) external onlyOwner initVer(1) {
        _init_Bridge(_relayerStake, _trustedRelayers);
        homeChainId = _homeChainId;
    }
    
    function isValidChainId(uint chainId) internal view override returns(bool) {
        return chainId == homeChainId;
    }
    
    function _resolveAsset(uint, address contractLocal) internal pure override returns(address) {
        return contractLocal;
    }
}