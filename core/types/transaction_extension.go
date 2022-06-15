package types

import "math/big"

type TxDataExtension interface {
	encryptedPayload() []byte
	decryptionKey() []byte
	batchIndex() uint64
	l1BlockNumber() uint64
	timestamp() *big.Int
	transactions() [][]byte
}

func (tx *DynamicFeeTx) encryptedPayload() []byte { return nil }
func (tx *DynamicFeeTx) decryptionKey() []byte    { return nil }
func (tx *DynamicFeeTx) batchIndex() uint64       { return 0 }
func (tx *DynamicFeeTx) l1BlockNumber() uint64    { return 0 }
func (tx *DynamicFeeTx) timestamp() *big.Int      { return nil }
func (tx *DynamicFeeTx) transactions() [][]byte   { return nil }

func (tx *AccessListTx) encryptedPayload() []byte { return nil }
func (tx *AccessListTx) decryptionKey() []byte    { return nil }
func (tx *AccessListTx) batchIndex() uint64       { return 0 }
func (tx *AccessListTx) l1BlockNumber() uint64    { return 0 }
func (tx *AccessListTx) timestamp() *big.Int      { return nil }
func (tx *AccessListTx) transactions() [][]byte   { return nil }

func (tx *LegacyTx) encryptedPayload() []byte { return nil }
func (tx *LegacyTx) decryptionKey() []byte    { return nil }
func (tx *LegacyTx) batchIndex() uint64       { return 0 }
func (tx *LegacyTx) l1BlockNumber() uint64    { return 0 }
func (tx *LegacyTx) timestamp() *big.Int      { return nil }
func (tx *LegacyTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumUnsignedTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumUnsignedTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumUnsignedTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumUnsignedTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumUnsignedTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumUnsignedTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumContractTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumContractTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumContractTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumContractTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumContractTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumContractTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumRetryTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumRetryTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumRetryTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumRetryTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumRetryTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumRetryTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumSubmitRetryableTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumSubmitRetryableTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumSubmitRetryableTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumSubmitRetryableTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumSubmitRetryableTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumSubmitRetryableTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumDepositTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumDepositTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumDepositTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumDepositTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumDepositTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumDepositTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumInternalTx) encryptedPayload() []byte { return nil }
func (tx *ArbitrumInternalTx) decryptionKey() []byte    { return nil }
func (tx *ArbitrumInternalTx) batchIndex() uint64       { return 0 }
func (tx *ArbitrumInternalTx) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumInternalTx) timestamp() *big.Int      { return nil }
func (tx *ArbitrumInternalTx) transactions() [][]byte   { return nil }

func (tx *ArbitrumLegacyTxData) encryptedPayload() []byte { return nil }
func (tx *ArbitrumLegacyTxData) decryptionKey() []byte    { return nil }
func (tx *ArbitrumLegacyTxData) batchIndex() uint64       { return 0 }
func (tx *ArbitrumLegacyTxData) l1BlockNumber() uint64    { return 0 }
func (tx *ArbitrumLegacyTxData) timestamp() *big.Int      { return nil }
func (tx *ArbitrumLegacyTxData) transactions() [][]byte   { return nil }
