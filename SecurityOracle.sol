// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract SecurityOracle {
    address public owner;
    uint256 public staticFee = 10 ether; // 10 LCAI
    uint256 public deepFee = 50 ether;   // 50 LCAI

    event AuditRequested(uint256 indexed taskId, address indexed client, address target, uint8 auditType);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function updateFees(uint256 _static, uint256 _deep) external onlyOwner {
        staticFee = _static;
        deepFee = _deep;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }

    function requestAudit(address target, uint8 auditType) external payable {
        uint256 fee = (auditType == 0) ? staticFee : deepFee;
        require(msg.value == fee, "Incorrect LCAI amount sent");
        
        emit AuditRequested(block.timestamp, msg.sender, target, auditType);
    }

    function withdrawFees() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}