# Dex223 QuoteSwap & ProtocolFeeCollector Detector Rules (v1.1)

- **EVM-006 (`dex223-quoteswap-exact-out-inversion`):** Detects assembly `revert(ptr, 32)` quote blocks that branch on `if (zeroForOne)` instead of `if (zeroForOne == exactInput)`.
- **EVM-007 (`dex223-quoteswap-retdata-length`):** Detects `delegatecall` quote wrappers checking `retdata.length >= 32` instead of `retdata.length == 32`.
- **EVM-008 (`protocol-fee-collector-gas-cap`):** Detects hardcoded `collectProtocol{gas: 300_000}` calls on pools that trigger lazy `CREATE2` token wrapper deployment.
- **EVM-009 (`erc4626-share-inflation`):** Detects `totalAssets()` / `convertToShares()` vault formulas without virtual share/asset offsets.
- **EVM-010 (`eip1153-transient-guard`):** Audits `tload`/`tstore` reentrancy locks across delegatecall boundaries.
- **EVM-011 (`uni-v4-hook-delta`):** Verifies `beforeSwap`/`afterSwap` hook return deltas cannot leave unsettled currency balances.
- **EVM-012 (`eip7702-delegation-guard`):** Detects `tx.origin == msg.sender` checks that break under EIP-7702 delegated EOAs.
- **EVM-013 (`view-reentrancy-oracle`):** Flags `get_virtual_price()` and pool invariant reads during unguarded ETH/ERC-223 callbacks.
- **EVM-014 (`permit2-witness-validation`):** Verifies `permitWitnessTransferFrom` binds `msg.sender` and target recipient in the EIP-712 witness struct.
- **EVM-015 (`merkle-double-hash-leaf`):** Flags `keccak256(abi.encodePacked(account, amount))` leaves without double hashing (`keccak256(bytes.concat(keccak256(...)))`).
