// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

import "./utils/Upgradeable.sol";
import "./interface/IERC20.sol";
import "./interface/IERC20Mintable.sol";
import "./interface/IERC20Burnable.sol";

abstract contract Bridge is Upgradeable {
    enum MessageType {
        TRANSFER
    }
    
    struct Relayer {
        bool status;
        uint64 statusEpoch;
        uint balance;
    }
    
    struct RelayersCountSnapshot {
        uint64 epoch;
        uint32 value;
    }
    
    struct Chain {
        address[] addresses;
        mapping(address => Relayer) relayers;
        RelayersCountSnapshot[2] rcs;
    }
    
    struct Random {
        uint64 epoch;
        uint256 value;
    }
    
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
    
    event MessageCreated(uint chainId, bytes32 messageHash);
    event MessageProcessed(uint chainId, bytes32 messageHash);
    
    uint private relayerStake;
    RandomSnapshot[2] private random;
    mapping(uint => ChainRelayers) private chains; // chainId => Chain
    uint private nextNonce;
    mapping(bytes32 => bool) private processedMessages; // message hash => processed or not
    address[] private trustedRelayers;

    
    // -------------------- VIRTUAL --------------------
    
    function isValidChainId(uint chainId) internal view virtual returns(bool);
    function _resolveAsset(uint chainId, address contractLocal) internal view virtual returns(address);
    
    // -------------------- INITIALIZE --------------------
    
    function _init_Bridge(uint _relayerStake, address[] calldata _trustedRelayers) internal ext {
        relayerStake = _relayerStake;
        
        for(uint i = 0; i < _trustedRelayers.length; i++)
            trustedRelayers.push(_trustedRelayers[i]);
    }
    
    // -------------------- UTILS --------------------
    
    modifier ext {
        _;
        updateRandom();
    }
    
    function getCurrentEpoch() private view returns(uint64) {
        return uint64(block.timestamp) / 60 / 20; // 20 minutes
    }
    
    function checkValidChainId(uint chainId) private view {
        require(
            isValidChainId(chainId),
            "Invalid chainId"
        );
    }
    
    function resolveAsset(uint chainId, address contractLocal) public view returns(address) {
        checkValidChainId(chainId);
        return _resolveAsset(chainId, contractLocal);
    }
    
    function isERC20Owner(address tokenContract) private view returns(bool) {
        (bool success, bytes memory data) = tokenContract.staticcall(abi.encodeWithSignature("owner()"));
        if(!success)
            return false;
            
        address decoded = abi.decode(data, (address));
        return decoded == address(this);
    }
    
    // -------------------- TRANSACTION INDEPENDENT RANDOM NUMBER --------------------
    
    function updateRandom() private {
        uint64 epoch = getCurrentEpoch();
        
        if(random[0].epoch == epoch)
            return;
        
        random[1] = random[0];
        
        random[0].epoch = epoch;
        random[0].value = uint256(blockhash(block.number - 1));
    }
    
    function getRandom(uint64 epoch) private view returns(uint256) {
        if(random[0].epoch < epoch)
            return random[0].value;
        
        return random[1].value;
    }
    
    // -------------------- RELAYERS COUNT SNAPSHOT --------------------
    
    function updateRelayersCount(uint chainId) private {
        uint64 epoch = getCurrentEpoch();
        
        if(chains[chainId].rcs[0] == epoch)
            return;
        
        chains[chainId].rcs[1] = chains[chainId].rcs[0];
        
        chains[chainId].rcs[0].epoch = epoch;
        chains[chainId].rcs[0].value = uint32(chains[chainId].addresses.length);
    }
    
    function getRelayersCount(uint chainId, uint64 epoch) private view returns(uint32) {
        if(chains[chainId].rcs[0].epoch < epoch)
            return chains[chainId].rcs[0].value;
        
        return chain[chainId].rcs[1].value;
    }
    
    // -------------------- SIGNATURES --------------------
    
    function verifySignature(bytes32 epochHash, Signature calldata signature) private pure returns(address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(abi.encodePacked(prefix, epochHash));
        return ecrecover(prefixedHash, signature.v, signature.r, signature.s);
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    function getMessageRelayers(
        uint chainId,
        uint64 sigEpoch,
        bytes32 epochHash
    ) private view returns(address[8] memory) {
        uint32 relayersCount = getRelayersCount(chainId, sigEpoch);
        require(
            relayersCount >= 8,
            "Not enough relayers"
        );
        
        address[8] memory selectedRelayers;
        for(uint8 i = 0; i < 8; i++) {
            // Get initial relayer index
            uint32 initialIndex = uint32(uint(keccak256(abi.encodePacked(
                epochHash,
                i
            ))));
            initialIndex = initialIndex * (relayersCount - 1) / 4294967295; // uint32 max
            
            // Get alternative relayer if inactive or duplicated
            uint32 relayerIndex = initialIndex;
            while(true) {
                address relayerAddr = relayers[chainId].addresses[relayerIndex];
                
                if(
                    relayers[chainId].relayers[relayerAddr].status == true
                    && relayers[chainId].relayers[relayerAddr].statusEpoch < sigEpoch
                ) {
                    bool isDuplicate = false;
                    
                    for(uint8 j = 0; j < i; j++)
                        if(selectedRelayers[j] == relayerAddr) {
                            isDuplicate = true;
                            break;
                        }
                    
                    if(!isDuplicate) {
                        selectedRelayers[i] = relayerAddr;
                        break; // while(true)
                    }
                }
                
                if(relayerIndex >= initialIndex) {
                    // Range initialIndex - relayersCount-1
                    if(relayerIndex == relayersCount - 1)
                        relayerIndex = 0;
                    else
                        relayerIndex++;
                }
                else {
                    // Range 0 - initialIndex-1
                    if(relayerIndex == initialIndex - 1)
                        revert("Not enough relayers");
                    else
                        relayerIndex++;
                }
            }
        }
        
        return selectedRelayers;
    }
    
    function checkSignatures(
        uint chainId,
        bytes32 messageHash,
        Signature[8] calldata signatures,
        uint64 sigEpoch
    ) private view returns(address[8] memory) {
        uint64 currentEpoch = getCurrentEpoch();
        
        require(
            sigEpoch == currentEpoch || sigEpoch == currentEpoch - 1,
            "Expired signatures"
        );
        
        bytes32 epochHash = keccak256(abi.encodePacked(
            messageHash,
            sigEpoch
        ));
        address[8] memory selectedRelayers = getMessageRelayers(chainId, sigEpoch, epochHash);
        
        for(uint8 i = 0; i < 8; i++)
            require(
                verifySignature(epochHash, signatures[i]) == selectedRelayers[i],
                "Invalid signature"
            );
        
        return selectedRelayers;
    }
    
    function relayerCheckMessage(uint chainId, bytes32 messageHash) public view returns(bool) {
        uint64 epoch = getCurrentEpoch();
        
        bytes32 epochHash = keccak256(abi.encodePacked(
            messageHash,
            epoch
        ));
        address[8] memory selectedRelayers = getMessageRelayers(chainId, epoch, epochHash);
        
        for(uint8 i = 0; i < 8; i++)
            if(selectedRelayers[i] == msg.sender)
                return true;
        return false;
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    // -------------------- MESSAGES --------------------
    
    function createMessage(uint chainId, MessageType messageType, bytes memory body) private returns(bytes memory) {
        bytes memory message = bytes.concat(
            abi.encode(
                block.chainid,
                chainId,
                nextNonce++,
                messageType
            ),
            body
        );
        emit MessageCreated(chainId, keccak256(message));
        return message;
    }
    
    function processMessage(
        bytes calldata message,
        Signature[8] calldata signatures,
        uint64 sigEpoch
    ) external payable ext {
        require(
            msg.value >= tx.gasprice * 21000,
            "Insufficient relayer fee"
        );
        
        require(
            msg.value % 8 == 0,
            "Relayer fee not divisible by 8"
        );
        
        require(
            message.length >= 4,
            "Message corrupted"
        );
        
        (
            uint srcChainId,
            uint dstChainId,
            , // nonce
            MessageType messageType
        ) = abi.decode(message, (
            uint,
            uint,
            uint,
            MessageType
        ));
        
        require(
            isValidChainId(srcChainId),
            "Source chainId rejected"
        );
        
        require(
            dstChainId == block.chainid,
            "Destination chainId mismatch"
        );
        
        bytes32 messageHash = keccak256(message);
        
        require(
            processedMessages[messageHash] == false,
            "Message already processed"
        );
        
        address[8] memory selectedRelayers = checkSignatures(srcChainId, messageHash, signatures, sigEpoch);
        
        if(messageType == MessageType.TRANSFER) {
            (
                , // srcChainId
                , // dstChainId,
                , // nonce
                , // messageType
                address srcDstContract,
                address dstAddress,
                uint value
            ) = abi.decode(message, (
                uint,
                uint,
                uint,
                MessageType,
                address,
                address,
                uint
            ));
            execTransfer(srcChainId, srcDstContract, dstAddress, value);
        }
        else
            revert("Invalid message type");
        
        uint feePerRelayer = msg.value / 8;
        for(uint8 i = 0; i < 8; i++)
            chains[srcChainId].relayers[ selectedRelayers[i] ].balance += feePerRelayer;
        
        processedMessages[messageHash] = true;
        emit MessageProcessed(srcChainId, messageHash);
    }
    
    // -------------------- RELAYER ACTIVATION --------------------
    
    function relayerGetStake(address relayerAddr) public view returns(uint) {
        for(uint8 i = 0; i < trustedRelayers.length; i++)
            if(trustedRelayers[i] == relayerAddr)
                return 0;
        
        return relayerStake;
    }
    
    function relayerActivate(uint chainId) external payable ext {
        checkValidChainId(chainId);
        
        require(
            chains[chainId].relayers[msg.sender].status == false,
            "Relayer already active"
        );
        
        require(
            chains[chainId].relayers[msg.sender].balance + msg.value >= relayerGetStake(msg.sender),
            "Insufficient stake amount"
        );
        
        uint64 epoch = getCurrentEpoch();
        
        require(
            chains[chainId].relayers[msg.sender].statusEpoch <= epoch - 2,
            "Not allowed in this epoch"
        );
        
        // statusEpoch = 0 means it never existed before
        if(chains[chainId].relayers[msg.sender].statusEpoch == 0) {
            updateRelayersCount(chainId);
            chains[chainId].addresses.push(msg.sender);
        }
        
        chain[chainId].relayers[msg.sender].status = true;
        chains[chainId].relayers[msg.sender].statusEpoch = epoch;
        chains[chainId].relayers[msg.sender].balance += msg.value;
    }
    
    // -------------------- RELAYER DEACTIVATION --------------------
    
    function relayerDeactivate(uint chainId) external ext {
        checkValidChainId(chainId);
        
        require(
            chains[chainId].relayers[msg.sender].status == true,
            "Relayer already inactive"
        );
        
        uint64 epoch = getCurrentEpoch();
        
        require(
            chains[chainId].relayers[msg.sender].statusEpoch <= epoch - 2,
            "Not allowed in this epoch"
        );
        
        chains[chainId].relayers[msg.sender].status = false;
        chains[chainId].relayers[msg.sender].statusEpoch = epoch;
    }
    
    // -------------------- RELAYER BALANCE --------------------
    
    function relayerGetBalance(uint chainId, address relayerAddr) external view returns(uint) {
        checkValidChainId(chainId);
        return chains[chainId].relayers[relayerAddr].balance;
    }
    
    function relayerGetStatus(uint chainId, address relayerAddr) external view returns(bool, uint64) {
        checkValidChainId(chainId);
        return chains[chainId].relayers[relayerAddr].status,
               chains[chainId].relayers[relayerAddr].statusEpoch;
    }
    
    function relayerGetWithdrawalMax(uint chainId, address relayerAddr) public view returns(uint) {
        checkValidChainId(chainId);
        
        uint maxAllowedValue = 0;
        uint thisRelayerStake = relayerGetStake(relayerAddr);
        
        // Stake + profit
        // 1000 (deactivate epoch)     - still used in consensus
        // 1001 (deactivate epoch + 1) - not used in consensus, but signatures are still valid
        // 1002 (current epoch)        - allowed
        if(
            chains[chainId].relayers[relayerAddr].status == false
            && chains[chainId].relayers[relayerAddr].statusEpoch <= getCurrentEpoch() - 2
        )
            maxAllowedValue = chains[chainId].relayers[relayerAddr].balance;
        
        // Only profit
        else if(chains[chainId].relayers[relayerAddr].balance > thisRelayerStake)
            maxAllowedValue = chains[chainId].relayers[relayerAddr].balance - thisRelayerStake;
        
        return maxAllowedValue;
    }
    
    function relayerWithdraw(uint chainId, address payable to, uint256 value) external ext {
        require(
            value > 0 && value <= relayerGetWithdrawalMax(chainId, msg.sender),
            "Withdrawal value out of allowed range"
        );
        
        to.transfer(value);
        chains[chainId].relayers[msg.sender].balance -= value;
    }
    
    // -------------------- TRANSFER: DEPOSIT --------------------
    
    function transferCommon(
        address srcContract,
        uint dstChainId,
        address dstAddress,
        uint value
    ) private returns(bytes memory) {
        require(
            value != 0,
            "Transfer value is 0"
        );
        
        return createMessage(dstChainId, MessageType.TRANSFER, abi.encode(
            resolveAsset(dstChainId, srcContract),
            dstAddress,
            value
        ));
    }
    
    function transfer(
        uint dstChainId,
        address dstAddress
    ) external payable ext returns(bytes memory) {
        return transferCommon(address(0), dstChainId, dstAddress, msg.value);
    }
    
    function transferERC20(
        address srcContract,
        uint dstChainId,
        address dstAddress,
        uint value
    ) external ext returns(bytes memory) {
        bytes memory message = transferCommon(srcContract, dstChainId, dstAddress, value);
        
        if(isERC20Owner(srcContract))
            IERC20Burnable(srcContract).burnFrom(msg.sender, value);
        else
            require(
                IERC20(srcContract).transferFrom(msg.sender, address(this), value),
                "ERC20 transfer failed"
            );
        
        return message;
    }
    
    // -------------------- TRANSFER: WITHDRAWAL --------------------
    
    function execTransfer(
        uint srcChainId,
        address srcDstContract,
        address dstAddress,
        uint value
    ) private {
        address dstContract = resolveAsset(srcChainId, srcDstContract);
        
        if(dstContract == address(0))
            payable(dstAddress).transfer(value);
        else if(isERC20Owner(dstContract))
            IERC20Mintable(dstContract).mint(dstAddress, value);
        else
            require(
                IERC20(dstContract).transfer(dstAddress, value),
                "ERC20 transfer failed"
            );
    }
}