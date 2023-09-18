// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// AtomicSwapMetaData contains all meta data concerning the AtomicSwap contract.
var AtomicSwapMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_weth\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"stateMutability\":\"payable\",\"type\":\"fallback\"},{\"inputs\":[],\"name\":\"WETH\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenArb\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_tokenSettle\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_startFactory\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_endFactory\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_pairStart\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_pairEnd\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amountIn\",\"type\":\"uint256\"}],\"name\":\"arb\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOut\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_startFactory\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_endFactory\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amountIn\",\"type\":\"uint256\"}],\"name\":\"backrun\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"liquidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"path\",\"type\":\"address[]\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"factory\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"fromThis\",\"type\":\"bool\"}],\"name\":\"swap\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"path\",\"type\":\"address[]\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"factory\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_pair\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"fromThis\",\"type\":\"bool\"}],\"name\":\"swapCheaper\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOut\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// AtomicSwapABI is the input ABI used to generate the binding from.
// Deprecated: Use AtomicSwapMetaData.ABI instead.
var AtomicSwapABI = AtomicSwapMetaData.ABI

// AtomicSwap is an auto generated Go binding around an Ethereum contract.
type AtomicSwap struct {
	AtomicSwapCaller     // Read-only binding to the contract
	AtomicSwapTransactor // Write-only binding to the contract
	AtomicSwapFilterer   // Log filterer for contract events
}

// AtomicSwapCaller is an auto generated read-only Go binding around an Ethereum contract.
type AtomicSwapCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AtomicSwapTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AtomicSwapTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AtomicSwapFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AtomicSwapFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AtomicSwapSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AtomicSwapSession struct {
	Contract     *AtomicSwap       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AtomicSwapCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AtomicSwapCallerSession struct {
	Contract *AtomicSwapCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// AtomicSwapTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AtomicSwapTransactorSession struct {
	Contract     *AtomicSwapTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// AtomicSwapRaw is an auto generated low-level Go binding around an Ethereum contract.
type AtomicSwapRaw struct {
	Contract *AtomicSwap // Generic contract binding to access the raw methods on
}

// AtomicSwapCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AtomicSwapCallerRaw struct {
	Contract *AtomicSwapCaller // Generic read-only contract binding to access the raw methods on
}

// AtomicSwapTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AtomicSwapTransactorRaw struct {
	Contract *AtomicSwapTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAtomicSwap creates a new instance of AtomicSwap, bound to a specific deployed contract.
func NewAtomicSwap(address common.Address, backend bind.ContractBackend) (*AtomicSwap, error) {
	contract, err := bindAtomicSwap(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AtomicSwap{AtomicSwapCaller: AtomicSwapCaller{contract: contract}, AtomicSwapTransactor: AtomicSwapTransactor{contract: contract}, AtomicSwapFilterer: AtomicSwapFilterer{contract: contract}}, nil
}

// NewAtomicSwapCaller creates a new read-only instance of AtomicSwap, bound to a specific deployed contract.
func NewAtomicSwapCaller(address common.Address, caller bind.ContractCaller) (*AtomicSwapCaller, error) {
	contract, err := bindAtomicSwap(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AtomicSwapCaller{contract: contract}, nil
}

// NewAtomicSwapTransactor creates a new write-only instance of AtomicSwap, bound to a specific deployed contract.
func NewAtomicSwapTransactor(address common.Address, transactor bind.ContractTransactor) (*AtomicSwapTransactor, error) {
	contract, err := bindAtomicSwap(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AtomicSwapTransactor{contract: contract}, nil
}

// NewAtomicSwapFilterer creates a new log filterer instance of AtomicSwap, bound to a specific deployed contract.
func NewAtomicSwapFilterer(address common.Address, filterer bind.ContractFilterer) (*AtomicSwapFilterer, error) {
	contract, err := bindAtomicSwap(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AtomicSwapFilterer{contract: contract}, nil
}

// bindAtomicSwap binds a generic wrapper to an already deployed contract.
func bindAtomicSwap(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := AtomicSwapMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AtomicSwap *AtomicSwapRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AtomicSwap.Contract.AtomicSwapCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AtomicSwap *AtomicSwapRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AtomicSwap.Contract.AtomicSwapTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AtomicSwap *AtomicSwapRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AtomicSwap.Contract.AtomicSwapTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AtomicSwap *AtomicSwapCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AtomicSwap.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AtomicSwap *AtomicSwapTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AtomicSwap.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AtomicSwap *AtomicSwapTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AtomicSwap.Contract.contract.Transact(opts, method, params...)
}

// WETH is a free data retrieval call binding the contract method 0xad5c4648.
//
// Solidity: function WETH() view returns(address)
func (_AtomicSwap *AtomicSwapCaller) WETH(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AtomicSwap.contract.Call(opts, &out, "WETH")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// WETH is a free data retrieval call binding the contract method 0xad5c4648.
//
// Solidity: function WETH() view returns(address)
func (_AtomicSwap *AtomicSwapSession) WETH() (common.Address, error) {
	return _AtomicSwap.Contract.WETH(&_AtomicSwap.CallOpts)
}

// WETH is a free data retrieval call binding the contract method 0xad5c4648.
//
// Solidity: function WETH() view returns(address)
func (_AtomicSwap *AtomicSwapCallerSession) WETH() (common.Address, error) {
	return _AtomicSwap.Contract.WETH(&_AtomicSwap.CallOpts)
}

// Arb is a paid mutator transaction binding the contract method 0x3437a611.
//
// Solidity: function arb(address _tokenArb, address _tokenSettle, address _startFactory, address _endFactory, address _pairStart, address _pairEnd, uint256 _amountIn) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapTransactor) Arb(opts *bind.TransactOpts, _tokenArb common.Address, _tokenSettle common.Address, _startFactory common.Address, _endFactory common.Address, _pairStart common.Address, _pairEnd common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.contract.Transact(opts, "arb", _tokenArb, _tokenSettle, _startFactory, _endFactory, _pairStart, _pairEnd, _amountIn)
}

// Arb is a paid mutator transaction binding the contract method 0x3437a611.
//
// Solidity: function arb(address _tokenArb, address _tokenSettle, address _startFactory, address _endFactory, address _pairStart, address _pairEnd, uint256 _amountIn) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapSession) Arb(_tokenArb common.Address, _tokenSettle common.Address, _startFactory common.Address, _endFactory common.Address, _pairStart common.Address, _pairEnd common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Arb(&_AtomicSwap.TransactOpts, _tokenArb, _tokenSettle, _startFactory, _endFactory, _pairStart, _pairEnd, _amountIn)
}

// Arb is a paid mutator transaction binding the contract method 0x3437a611.
//
// Solidity: function arb(address _tokenArb, address _tokenSettle, address _startFactory, address _endFactory, address _pairStart, address _pairEnd, uint256 _amountIn) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapTransactorSession) Arb(_tokenArb common.Address, _tokenSettle common.Address, _startFactory common.Address, _endFactory common.Address, _pairStart common.Address, _pairEnd common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Arb(&_AtomicSwap.TransactOpts, _tokenArb, _tokenSettle, _startFactory, _endFactory, _pairStart, _pairEnd, _amountIn)
}

// Backrun is a paid mutator transaction binding the contract method 0x86f89bd2.
//
// Solidity: function backrun(address _token, address _startFactory, address _endFactory, uint256 _amountIn) returns()
func (_AtomicSwap *AtomicSwapTransactor) Backrun(opts *bind.TransactOpts, _token common.Address, _startFactory common.Address, _endFactory common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.contract.Transact(opts, "backrun", _token, _startFactory, _endFactory, _amountIn)
}

// Backrun is a paid mutator transaction binding the contract method 0x86f89bd2.
//
// Solidity: function backrun(address _token, address _startFactory, address _endFactory, uint256 _amountIn) returns()
func (_AtomicSwap *AtomicSwapSession) Backrun(_token common.Address, _startFactory common.Address, _endFactory common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Backrun(&_AtomicSwap.TransactOpts, _token, _startFactory, _endFactory, _amountIn)
}

// Backrun is a paid mutator transaction binding the contract method 0x86f89bd2.
//
// Solidity: function backrun(address _token, address _startFactory, address _endFactory, uint256 _amountIn) returns()
func (_AtomicSwap *AtomicSwapTransactorSession) Backrun(_token common.Address, _startFactory common.Address, _endFactory common.Address, _amountIn *big.Int) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Backrun(&_AtomicSwap.TransactOpts, _token, _startFactory, _endFactory, _amountIn)
}

// Liquidate is a paid mutator transaction binding the contract method 0x28a07025.
//
// Solidity: function liquidate() returns()
func (_AtomicSwap *AtomicSwapTransactor) Liquidate(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AtomicSwap.contract.Transact(opts, "liquidate")
}

// Liquidate is a paid mutator transaction binding the contract method 0x28a07025.
//
// Solidity: function liquidate() returns()
func (_AtomicSwap *AtomicSwapSession) Liquidate() (*types.Transaction, error) {
	return _AtomicSwap.Contract.Liquidate(&_AtomicSwap.TransactOpts)
}

// Liquidate is a paid mutator transaction binding the contract method 0x28a07025.
//
// Solidity: function liquidate() returns()
func (_AtomicSwap *AtomicSwapTransactorSession) Liquidate() (*types.Transaction, error) {
	return _AtomicSwap.Contract.Liquidate(&_AtomicSwap.TransactOpts)
}

// Swap is a paid mutator transaction binding the contract method 0x0cc73263.
//
// Solidity: function swap(address[] path, uint256 amountIn, address factory, address recipient, bool fromThis) returns()
func (_AtomicSwap *AtomicSwapTransactor) Swap(opts *bind.TransactOpts, path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.contract.Transact(opts, "swap", path, amountIn, factory, recipient, fromThis)
}

// Swap is a paid mutator transaction binding the contract method 0x0cc73263.
//
// Solidity: function swap(address[] path, uint256 amountIn, address factory, address recipient, bool fromThis) returns()
func (_AtomicSwap *AtomicSwapSession) Swap(path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Swap(&_AtomicSwap.TransactOpts, path, amountIn, factory, recipient, fromThis)
}

// Swap is a paid mutator transaction binding the contract method 0x0cc73263.
//
// Solidity: function swap(address[] path, uint256 amountIn, address factory, address recipient, bool fromThis) returns()
func (_AtomicSwap *AtomicSwapTransactorSession) Swap(path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Swap(&_AtomicSwap.TransactOpts, path, amountIn, factory, recipient, fromThis)
}

// SwapCheaper is a paid mutator transaction binding the contract method 0x7e372601.
//
// Solidity: function swapCheaper(address[] path, uint256 amountIn, address factory, address recipient, address _pair, bool fromThis) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapTransactor) SwapCheaper(opts *bind.TransactOpts, path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, _pair common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.contract.Transact(opts, "swapCheaper", path, amountIn, factory, recipient, _pair, fromThis)
}

// SwapCheaper is a paid mutator transaction binding the contract method 0x7e372601.
//
// Solidity: function swapCheaper(address[] path, uint256 amountIn, address factory, address recipient, address _pair, bool fromThis) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapSession) SwapCheaper(path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, _pair common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.Contract.SwapCheaper(&_AtomicSwap.TransactOpts, path, amountIn, factory, recipient, _pair, fromThis)
}

// SwapCheaper is a paid mutator transaction binding the contract method 0x7e372601.
//
// Solidity: function swapCheaper(address[] path, uint256 amountIn, address factory, address recipient, address _pair, bool fromThis) returns(uint256 amountOut)
func (_AtomicSwap *AtomicSwapTransactorSession) SwapCheaper(path []common.Address, amountIn *big.Int, factory common.Address, recipient common.Address, _pair common.Address, fromThis bool) (*types.Transaction, error) {
	return _AtomicSwap.Contract.SwapCheaper(&_AtomicSwap.TransactOpts, path, amountIn, factory, recipient, _pair, fromThis)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_AtomicSwap *AtomicSwapTransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _AtomicSwap.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_AtomicSwap *AtomicSwapSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Fallback(&_AtomicSwap.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_AtomicSwap *AtomicSwapTransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _AtomicSwap.Contract.Fallback(&_AtomicSwap.TransactOpts, calldata)
}
