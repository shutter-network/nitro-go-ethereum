// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type ArbitrumChainParams struct {
	EnableArbOS               bool
	AllowDebugPrecompiles     bool
	DataAvailabilityCommittee bool
	InitialArbOSVersion       uint64
	InitialChainOwner         common.Address
}

func (c *ChainConfig) IsArbitrum() bool {
	return c.ArbitrumChainParams.EnableArbOS
}

func (c *ChainConfig) DebugMode() bool {
	return c.ArbitrumChainParams.AllowDebugPrecompiles
}

func ArbitrumOneParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               true,
		AllowDebugPrecompiles:     false,
		DataAvailabilityCommittee: false,
		// Not used as arbitrum one has init data
		InitialArbOSVersion: 1,
		InitialChainOwner:   common.Address{},
	}
}

func ArbitrumTestnetParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               true,
		AllowDebugPrecompiles:     false,
		DataAvailabilityCommittee: false,
		InitialArbOSVersion:       1,
		InitialChainOwner:         common.Address{}, // TODO
	}
}

func ArbitrumDevTestParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               true,
		AllowDebugPrecompiles:     true,
		DataAvailabilityCommittee: false,
		InitialArbOSVersion:       4,
		InitialChainOwner:         common.Address{},
	}
}

func ArbitrumDevTestDASParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               true,
		AllowDebugPrecompiles:     true,
		DataAvailabilityCommittee: true,
		InitialArbOSVersion:       4,
		InitialChainOwner:         common.Address{},
	}
}

func ArbitrumDevnetDASParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               true,
		AllowDebugPrecompiles:     false,
		DataAvailabilityCommittee: true,
		InitialArbOSVersion:       3,
		InitialChainOwner:         common.HexToAddress("0x186B56023d42B2B4E7616589a5C62EEf5FCa21DD"),
	}
}

func DisableArbitrumParams() ArbitrumChainParams {
	return ArbitrumChainParams{
		EnableArbOS:               false,
		AllowDebugPrecompiles:     false,
		DataAvailabilityCommittee: false,
		InitialArbOSVersion:       0,
		InitialChainOwner:         common.Address{},
	}
}

func ArbitrumOneChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(412345),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArbitrumChainParams: ArbitrumOneParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

func ArbitrumTestnetChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(421612),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArbitrumChainParams: ArbitrumTestnetParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

func ArbitrumDevTestChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(412346),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArbitrumChainParams: ArbitrumDevTestParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

func ArbitrumDevTestDASChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(412347),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArbitrumChainParams: ArbitrumDevTestDASParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

func ArbitrumDevnetDASChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(421702),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArbitrumChainParams: ArbitrumDevnetDASParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

func ShutterizedArbitrumDevTestChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:             big.NewInt(452346),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),

		BatchCounterAddress:       common.HexToAddress("0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"),
		EonKeyBroadcastAddress:    common.HexToAddress("0x0165878A594ca255338adfa4d48449f69242Eb8F"),
		CollatorConfigListAddress: common.HexToAddress("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"),

		ArbitrumChainParams: ArbitrumDevTestParams(),
		Clique: &CliqueConfig{
			Period: 0,
			Epoch:  0,
		},
	}
}

var ArbitrumSupportedChainConfigs = []*ChainConfig{
	ArbitrumOneChainConfig(),
	ArbitrumTestnetChainConfig(),
	ArbitrumDevTestChainConfig(),
	ArbitrumDevTestDASChainConfig(),
	ArbitrumDevnetDASChainConfig(),

	ShutterizedArbitrumDevTestChainConfig(),
}
