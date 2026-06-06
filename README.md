# RTSecure 🛡️

RTSecure is a decentralized, AI-driven Smart Contract Security Oracle built for the **Lightchain AI** ecosystem. It provides real-time vulnerability scanning, combining rapid local syntactic analysis with deep cognitive threat profiling powered by Lightchain's decentralized worker pool running the **Neural-Llama-3-70B** model.

RTSecure safeguards ecosystem deployments by identifying critical vulnerabilities (SWC registries), analyzing gas optimizations, and generating professional PDF audit dossiers secured on-chain.

---

## 🚀 Core Features

- **Dual-Tier Audit Engine**:
  - **Standard Audit (Tier 1)**: Instant, zero-gas/low-fee local syntactic analysis matching signatures against established SWC vulnerability patterns (Reentrancy, Phishing vectors, Logic DoS, and dangerous Assembly blocks).
  - **Red Team Audit (Tier 2)**: Deep cognitive analysis running via Lightchain's `Neural-Llama-3-70B` model to trace cross-function logic exploits, front-running (MEV) parameters, and price oracle dependencies.
- **On-Chain Oracle Architecture**: Leverages `SecurityOracle.sol` to anchor audit logs on-chain via dedicated event streams (`AuditRequested`), ensuring immutable verification records.
- **Commercial Gas Profiling**: Automatically screens for high-performance optimization patterns, such as pre-incrementing loops (`++i`), external visibility overrides, and missing `immutable` states.
- **Dossier Generator**: Dynamically outputs sleek, professional PDF security matrices equipped with automated threat meter graphics and a verifiable **LCAI Verified** trust badge.
- **Admin Command Center**: A secure, embedded administration panel allowing the contract owner to update global scan fees, track native treasury collection, and manage ownership variables dynamically.

---

## 🛠️ Architecture Overview

RTSecure is split across three distinct operational layers:

1. **Frontend UI (`index.html`)**: A scannable, developer-centric developer terminal layout that interfaces with Web3 injection wallets (MetaMask), controls payment interaction, and processes the final PDF assembly.
2. **Serverless Traffic Router (`Cloudflare Worker`)**: A highly optimized edge router managing secure cross-origin requests (CORS), checking source verification from `LightScan`, and maintaining private authorization handshakes with the inference cluster.
3. **Smart Contract (`SecurityOracle.sol`)**: The protocol's economic and event anchor responsible for executing strict pay-to-scan access controls and emitting global event states.

---

## 📦 Smart Contract Specifications

The underlying oracle enforces the following fee metrics directly on the Lightchain Network:

- **Standard Static Fee**: `10 LCAI`
- **Deep Red Team Fee**: `50 LCAI`

### Key Methods Available
- `requestAudit(address target, uint8 auditType)`: Triggered by clients to pay the required fee and broadcast a global audit request.
- `updateFees(uint256 _static, uint256 _deep)`: Restricts modification of system pricing models exclusively to the contract deployer.
- `withdrawFees()`: Collects native contract revenue and forwards it safely to the verified owner address.

---

## ⚙️ Backend Environment Setup

To deploy the backend edge router (`worker.js`) inside your Cloudflare Dashboard, configuration parameters must be anchored within your environment settings:

```bash
# Bind the following variables in your Worker Settings -> Variables panel:
AIVM_API_KEY="your_lightchain_ai_inference_secret"
AIVM_WALLET="your_developer_portal_wallet_address"
