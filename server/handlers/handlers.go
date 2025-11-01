package handlers


import (
	"sync"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
)

type ServerHandler func(*core.ImplantConnection, []byte) *sliverpb.Envelope

var (
	tunnelHandlerMutex = &sync.Mutex{}
)

func GetSystemHandlers() map[uint32]Handler {
	return map[uint32]Handler{
		// ... existing handlers ...
		
		// Bloop Handlers
		sliverpb.MsgBloopEncrypt:       BloopEncryptHandler,
		sliverpb.MsgBloopProcessInject: BloopProcessInjectHandler,
	}
}


// GetHandlers - Returns a map of server-side msg handlers
func GetHandlers() map[uint32]ServerHandler {
	return map[uint32]ServerHandler{
		// Sessions
		sliverpb.MsgRegister:    registerSessionHandler,
		sliverpb.MsgTunnelData:  tunnelDataHandler,
		sliverpb.MsgTunnelClose: tunnelCloseHandler,
		sliverpb.MsgPing:        pingHandler,
		sliverpb.MsgSocksData:   socksDataHandler,

		// Beacons
		sliverpb.MsgBeaconRegister: beaconRegisterHandler,
		sliverpb.MsgBeaconTasks:    beaconTasksHandler,

		// Pivots
		sliverpb.MsgPivotPeerEnvelope: pivotPeerEnvelopeHandler,
		sliverpb.MsgPivotPeerFailure:  pivotPeerFailureHandler,
	}
}

// GetNonPivotHandlers - Server handlers for pivot connections, its important
// to avoid a pivot handler from calling a pivot handler and causing a recursive
// call stack
func GetNonPivotHandlers() map[uint32]ServerHandler {
	return map[uint32]ServerHandler{
		// Sessions
		sliverpb.MsgRegister:    registerSessionHandler,
		sliverpb.MsgTunnelData:  tunnelDataHandler,
		sliverpb.MsgTunnelClose: tunnelCloseHandler,
		sliverpb.MsgPing:        pingHandler,
		sliverpb.MsgSocksData:   socksDataHandler,

		// Beacons - Not currently supported in pivots
	}
}
