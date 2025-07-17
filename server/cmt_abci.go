package server

//import (
//	"context"
//
//	abci "github.com/tendermint/tendermint/abci/types"
//
//	servertypes "github.com/cosmos/cosmos-sdk/server/types"
//)

//type cometABCIWrapper struct {
//	app servertypes.ABCI
//}
//
//func NewCometABCIWrapper(app servertypes.ABCI) abci.Application {
//	return cometABCIWrapper{app: app}
//}
//
//func (w cometABCIWrapper) Info(info abci.RequestInfo) abci.ResponseInfo {
//	return w.app.Info(info)
//}
//
//func (w cometABCIWrapper) SetOption(option abci.RequestSetOption) abci.ResponseSetOption {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) Query(query abci.RequestQuery) abci.ResponseQuery {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) CheckTx(tx abci.RequestCheckTx) abci.ResponseCheckTx {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) InitChain(chain abci.RequestInitChain) abci.ResponseInitChain {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) BeginBlock(block abci.RequestBeginBlock) abci.ResponseBeginBlock {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) DeliverTx(tx abci.RequestDeliverTx) abci.ResponseDeliverTx {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) EndBlock(block abci.RequestEndBlock) abci.ResponseEndBlock {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) Commit() abci.ResponseCommit {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) ListSnapshots(snapshots abci.RequestListSnapshots) abci.ResponseListSnapshots {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) OfferSnapshot(snapshot abci.RequestOfferSnapshot) abci.ResponseOfferSnapshot {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) LoadSnapshotChunk(chunk abci.RequestLoadSnapshotChunk) abci.ResponseLoadSnapshotChunk {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) ApplySnapshotChunk(chunk abci.RequestApplySnapshotChunk) abci.ResponseApplySnapshotChunk {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (w cometABCIWrapper) Info(_ context.Context, req *abci.RequestInfo) (*abci.ResponseInfo, error) {
//	return w.app.Info(req)
//}
//
//func (w cometABCIWrapper) Query(ctx context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
//	return w.app.Query(ctx, req)
//}
//
//func (w cometABCIWrapper) CheckTx(_ context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTx, error) {
//	return w.app.CheckTx(req)
//}
//
//func (w cometABCIWrapper) InitChain(_ context.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
//	return w.app.InitChain(req)
//}
//
//func (w cometABCIWrapper) Commit(_ context.Context, _ *abci.RequestCommit) (*abci.ResponseCommit, error) {
//	return w.app.Commit()
//}
//
//func (w cometABCIWrapper) ListSnapshots(_ context.Context, req *abci.RequestListSnapshots) (*abci.ResponseListSnapshots, error) {
//	return w.app.ListSnapshots(req)
//}
//
//func (w cometABCIWrapper) OfferSnapshot(_ context.Context, req *abci.RequestOfferSnapshot) (*abci.ResponseOfferSnapshot, error) {
//	return w.app.OfferSnapshot(req)
//}
//
//func (w cometABCIWrapper) LoadSnapshotChunk(_ context.Context, req *abci.RequestLoadSnapshotChunk) (*abci.ResponseLoadSnapshotChunk, error) {
//	return w.app.LoadSnapshotChunk(req)
//}
//
//func (w cometABCIWrapper) ApplySnapshotChunk(_ context.Context, req *abci.RequestApplySnapshotChunk) (*abci.ResponseApplySnapshotChunk, error) {
//	return w.app.ApplySnapshotChunk(req)
//}
