package arbitrum

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

type APIBackend struct {
	b *Backend
}

func createRegisterAPIBackend(backend *Backend) {
	backend.apiBackend = &APIBackend{
		b: backend,
	}
	backend.stack.RegisterAPIs(backend.apiBackend.GetAPIs())
}

func (a *APIBackend) GetAPIs() []rpc.API {
	apis := ethapi.GetAPIs(a)

	apis = append(apis, rpc.API{
		Namespace: "eth",
		Version:   "1.0",
		Service:   filters.NewPublicFilterAPI(a, false, 5*time.Minute),
		Public:    true,
	})

	apis = append(apis, rpc.API{
		Namespace: "net",
		Version:   "1.0",
		Service:   NewPublicNetAPI(a.ChainConfig().ChainID.Uint64()),
		Public:    true,
	})

	apis = append(apis, rpc.API{
		Namespace: "txpool",
		Version:   "1.0",
		Service:   NewPublicTxPoolAPI(),
		Public:    true,
	})

	apis = append(apis, tracers.APIs(a)...)

	return apis
}

func (a *APIBackend) blockChain() *core.BlockChain {
	return a.b.arb.BlockChain()
}

func (a *APIBackend) GetArbitrumNode() interface{} {
	return a.b.arb.ArbNode()
}

// General Ethereum API
func (a *APIBackend) SyncProgress() ethereum.SyncProgress {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(0), nil // there's no tips in L2
}

func (a *APIBackend) FeeHistory(
	ctx context.Context,
	blocks int,
	newestBlock rpc.BlockNumber,
	rewardPercentiles []float64,
) (*big.Int, [][]*big.Int, []*big.Int, []float64, error) {

	if core.GetArbOSComputeRate == nil {
		return nil, nil, nil, nil, errors.New("ArbOS not installed")
	}

	nitroGenesis := core.NitroGenesisBlock
	newestBlock, latestBlock := ClipToPostNitroGenesis(a, newestBlock)

	maxFeeHistory := int(a.b.config.FeeHistoryMaxBlockCount)
	if blocks > maxFeeHistory {
		log.Warn("Sanitizing fee history length", "requested", blocks, "truncated", maxFeeHistory)
		blocks = maxFeeHistory
	}
	if blocks < 1 {
		// returning with no data and no error means there are no retrievable blocks
		return common.Big0, nil, nil, nil, nil
	}

	// don't attempt to include blocks before genesis
	if rpc.BlockNumber(blocks) > (newestBlock - nitroGenesis) {
		blocks = int(newestBlock - nitroGenesis + 1)
	}
	oldestBlock := int(newestBlock) + 1 - blocks

	// inform that tipping has no effect on inclusion
	rewards := make([][]*big.Int, blocks)
	zeros := make([]*big.Int, len(rewardPercentiles))
	for i := range zeros {
		zeros[i] = common.Big0
	}
	for i := range rewards {
		rewards[i] = zeros
	}
	if len(rewardPercentiles) == 0 {
		rewards = nil
	}

	gasUsed := make([]float64, blocks)
	basefees := make([]*big.Int, blocks+1) // the RPC semantics are to predict the future value

	// use the most recent average compute rate for all blocks
	// note: while we could query this value for each block, it'd be prohibitively expensive
	state, _, err := a.StateAndHeaderByNumber(ctx, rpc.BlockNumber(newestBlock))
	if err != nil {
		return common.Big0, nil, nil, nil, err
	}
	computeRate, err := core.GetArbOSComputeRate(state)
	if err != nil {
		return common.Big0, nil, nil, nil, err
	}

	// In vanilla geth, this RPC returns the gasUsed ratio so a client can infer how the basefee will change
	// To emulate this, we translate the compute rate into something like that, centered at an analogous 0.5
	fullnessAnalogue := computeRate / 2
	if fullnessAnalogue > 1.0 {
		fullnessAnalogue = 1.0
	}
	for i := range gasUsed {
		gasUsed[i] = fullnessAnalogue
	}

	// collect the basefees
	baseFeeLookup := newestBlock + 1
	if newestBlock == latestBlock {
		baseFeeLookup = newestBlock
	}
	for block := oldestBlock; block <= int(baseFeeLookup); block++ {
		header, err := a.HeaderByNumber(ctx, rpc.BlockNumber(block))
		if err != nil {
			return common.Big0, nil, nil, nil, err
		}
		basefees[block-oldestBlock] = header.BaseFee
	}
	if newestBlock == latestBlock {
		basefees[blocks] = basefees[blocks-1] // guess the basefee won't change
	}

	return big.NewInt(int64(oldestBlock)), rewards, basefees, gasUsed, nil
}

func (a *APIBackend) ChainDb() ethdb.Database {
	return a.b.chainDb
}

func (a *APIBackend) AccountManager() *accounts.Manager {
	return a.b.stack.AccountManager()
}

func (a *APIBackend) ExtRPCEnabled() bool {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) RPCGasCap() uint64 {
	return a.b.config.RPCGasCap
}

func (a *APIBackend) RPCTxFeeCap() float64 {
	return a.b.config.RPCTxFeeCap
}

func (a *APIBackend) RPCEVMTimeout() time.Duration {
	return a.b.config.RPCEVMTimeout
}

func (a *APIBackend) UnprotectedAllowed() bool {
	return true // TODO: is that true?
}

// Blockchain API
func (a *APIBackend) SetHead(number uint64) {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	return HeaderByNumber(a.blockChain(), number), nil
}

func (a *APIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return a.blockChain().GetHeaderByHash(hash), nil
}

func HeaderByNumber(blockchain *core.BlockChain, number rpc.BlockNumber) *types.Header {
	if number == rpc.LatestBlockNumber || number == rpc.PendingBlockNumber {
		return blockchain.CurrentBlock().Header()
	}
	return blockchain.GetHeaderByNumber(uint64(number.Int64()))
}

func HeaderByNumberOrHash(blockchain *core.BlockChain, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	number, isnum := blockNrOrHash.Number()
	if isnum {
		return HeaderByNumber(blockchain, number), nil
	}
	hash, ishash := blockNrOrHash.Hash()
	if ishash {
		return blockchain.GetHeaderByHash(hash), nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (a *APIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	return HeaderByNumberOrHash(a.blockChain(), blockNrOrHash)
}

func (a *APIBackend) CurrentHeader() *types.Header {
	return a.blockChain().CurrentHeader()
}

func (a *APIBackend) CurrentBlock() *types.Block {
	return a.blockChain().CurrentBlock()
}

func (a *APIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	if number == rpc.LatestBlockNumber || number == rpc.PendingBlockNumber {
		return a.blockChain().CurrentBlock(), nil
	}
	return a.blockChain().GetBlockByNumber(uint64(number.Int64())), nil
}

func (a *APIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return a.blockChain().GetBlockByHash(hash), nil
}

func (a *APIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	number, isnum := blockNrOrHash.Number()
	if isnum {
		return a.BlockByNumber(ctx, number)
	}
	hash, ishash := blockNrOrHash.Hash()
	if ishash {
		return a.BlockByHash(ctx, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (a *APIBackend) stateAndHeaderFromHeader(header *types.Header, err error) (*state.StateDB, *types.Header, error) {
	if err != nil {
		return nil, header, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	state, err := a.blockChain().StateAt(header.Root)
	return state, header, err
}

func (a *APIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return a.stateAndHeaderFromHeader(a.HeaderByNumber(ctx, number))
}

func (a *APIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return a.stateAndHeaderFromHeader(a.HeaderByNumberOrHash(ctx, blockNrOrHash))
}

func (a *APIBackend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, checkLive bool, preferDisk bool) (statedb *state.StateDB, err error) {
	// DEV: This assumes that `StateAtBlock` only accesses the blockchain and chainDb fields
	return eth.NewArbEthereum(a.b.arb.BlockChain(), a.ChainDb()).StateAtBlock(block, reexec, base, checkLive, preferDisk)
}

func (a *APIBackend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (core.Message, vm.BlockContext, *state.StateDB, error) {
	// DEV: This assumes that `StateAtTransaction` only accesses the blockchain and chainDb fields
	return eth.NewArbEthereum(a.b.arb.BlockChain(), a.ChainDb()).StateAtTransaction(block, txIndex, reexec)
}

func (a *APIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return a.blockChain().GetReceiptsByHash(hash), nil
}

func (a *APIBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	if header := a.blockChain().GetHeaderByHash(hash); header != nil {
		return a.blockChain().GetTd(hash, header.Number.Uint64())
	}
	return nil
}

func (a *APIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmConfig *vm.Config) (*vm.EVM, func() error, error) {
	vmError := func() error { return nil }
	if vmConfig == nil {
		vmConfig = a.blockChain().GetVMConfig()
	}
	txContext := core.NewEVMTxContext(msg)
	context := core.NewEVMBlockContext(header, a.blockChain(), nil)
	return vm.NewEVM(context, txContext, state, a.blockChain().Config(), *vmConfig), vmError, nil
}

func (a *APIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return a.blockChain().SubscribeChainEvent(ch)
}

func (a *APIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return a.blockChain().SubscribeChainHeadEvent(ch)
}

func (a *APIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return a.blockChain().SubscribeChainSideEvent(ch)
}

// Transaction pool API
func (a *APIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return a.b.EnqueueL2Message(ctx, signedTx)
}

func (a *APIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(a.b.chainDb, txHash)
	return tx, blockHash, blockNumber, index, nil
}

func (a *APIBackend) GetPoolTransactions() (types.Transactions, error) {
	// Arbitrum doesn't have a pool
	return types.Transactions{}, nil
}

func (a *APIBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	// Arbitrum doesn't have a pool
	return nil
}

func (a *APIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	stateDB, err := a.blockChain().State()
	if err != nil {
		return 0, err
	}
	return stateDB.GetNonce(addr), nil
}

func (a *APIBackend) Stats() (pending int, queued int) {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) TxPoolContentFrom(addr common.Address) (types.Transactions, types.Transactions) {
	panic("not implemented") // TODO: Implement
}

func (a *APIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return a.b.SubscribeNewTxsEvent(ch)
}

// Filter API
func (a *APIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := a.b.bloomIndexer.Sections()
	return a.b.config.BloomBitsBlocks, sections
}

func (a *APIBackend) GetLogs(ctx context.Context, blockHash common.Hash) ([][]*types.Log, error) {
	receipts := a.blockChain().GetReceiptsByHash(blockHash)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (a *APIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, a.b.bloomRequests)
	}
}

func (a *APIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return a.blockChain().SubscribeLogsEvent(ch)
}

func (a *APIBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	//Arbitrum doesn't really need pending logs. Logs are published as soon as we know them..
	return a.SubscribeLogsEvent(ch)
}

func (a *APIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return a.blockChain().SubscribeRemovedLogsEvent(ch)
}

func (a *APIBackend) ChainConfig() *params.ChainConfig {
	return a.blockChain().Config()
}

func (a *APIBackend) Engine() consensus.Engine {
	return a.blockChain().Engine()
}

type GetsCurrentBlock interface {
	CurrentBlock() *types.Block
}

func ClipToPostNitroGenesis(getter GetsCurrentBlock, blockNum rpc.BlockNumber) (rpc.BlockNumber, rpc.BlockNumber) {
	currentBlock := rpc.BlockNumber(getter.CurrentBlock().NumberU64())
	if blockNum == rpc.LatestBlockNumber || blockNum == rpc.PendingBlockNumber {
		blockNum = currentBlock
	}
	if blockNum > currentBlock {
		blockNum = currentBlock
	}
	if blockNum < core.NitroGenesisBlock {
		blockNum = core.NitroGenesisBlock
	}
	return blockNum, currentBlock
}
