# 🛡️ evm-bounty-guard

**Zero-dependency static security analyzer for EVM & Solidity smart contracts** — purpose-built for auditing DeFi pools, ERC-20/ERC-223 token bridges, `CREATE2` deterministic factories, and custodial routers.

[![Release](https://img.shields.io/badge/release-v1.0.0-brightgreen)](https://github.com/myhubstat/evm-bounty-guard/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 🔍 Built-in Vulnerability Detectors

| Detector ID | Severity | Pattern Detected |
|---|---|---|
| `EBG-001` | **Critical** | `tokenReceived` / ERC-223 callback state mutation or external call without reentrancy lock |
| `EBG-002` | **High** | Unchecked low-level `.call(...)` / optimistic ERC-20 transfer ignoring boolean return data |
| `EBG-003` | **High** | Permissionless `sweepToken` / `unwrapWETH` / `rescueERC20` on contracts holding custodial deposits |
| `EBG-004` | **Medium** | Hardcoded `POOL_INIT_CODE_HASH` mismatch risk or unvalidated `CREATE2` pool caller |
| `EBG-005` | **Medium** | `address(0)` recipient in fee/liquidity collection permanently burning ERC-20/ERC-223 balances |

## 🚀 Quick Start

```bash
python evm_guard.py path/to/contracts/ --format markdown
```

## 💳 Sponsorship & Bounty Settlement Rails

- **Base / Ethereum / Arbitrum / Optimism / Polygon / BSC (`USDC` / `USDT` / `ETH`):** `0x669fBa588D75577610459a2577eabdbbBa080e4A`
- **Tron Network (`USDT-TRC20`):** `TMbSRkXiuURMnMAvHp6p7Fpr5BrzU3YMDB`
