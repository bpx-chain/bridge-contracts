// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

interface IERC20Burnable {
    function burnFrom(address account, uint256 amount) external;
}