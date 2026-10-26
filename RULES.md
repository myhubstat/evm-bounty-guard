# Dex223 QuoteSwap & ProtocolFeeCollector Detector Rules (v1.1)

- **EVM-006 (`dex223-quoteswap-exact-out-inversion`):** Detects assembly `revert(ptr, 32)` quote blocks that branch on `if (zeroForOne)` instead of `if (zeroForOne == exactInput)`.
- **EVM-007 (`dex223-quoteswap-retdata-length`):** Detects `delegatecall` quote wrappers checking `retdata.length >= 32` instead of `retdata.length == 32`.
- **EVM-008 (`protocol-fee-collector-gas-cap`):** Detects hardcoded `collectProtocol{gas: 300_000}` calls on pools that trigger lazy `CREATE2` token wrapper deployment.
- **EVM-009 (`erc4626-share-inflation`):** Detects `totalAssets()` / `convertToShares()` vault formulas without virtual share/asset offsets.
