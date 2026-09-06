package main

import (
	"sort"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	mmext_database "github.com/PretendoNetwork/nex-protocols-common-go/v2/matchmake-extension/database"
	match_making_types "github.com/PretendoNetwork/nex-protocols-go/v2/match-making/types"
	matchmake_extension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"
)

// browseMatchmakeSessionStable is a drop-in replacement for the common lib's
// BrowseMatchmakeSession handler that fixes two FFE server-list problems:
//
//   - Hidden locked rooms: FFE's search sends attribute[4]=0 (the lock flag),
//     so the stock filter excludes any pin/locked room. We blank the configured
//     "hider" attributes (default index 4) so those rooms show up.
//   - Shuffling/duplicate rows: the underlying query has no ORDER BY for FFE's
//     selection method, so Postgres returns rows in an unstable order. We sort
//     and de-duplicate the results by gathering ID so consecutive browses return
//     an identical, unique-ordered list.
//
// It deliberately does NOT raise the result count above what the client asks
// for. FFE sizes its server-list buffer for the count it requests, so returning
// more overruns that buffer and crashes the console. The DB layer already limits
// to the client's ResultRange.
//
// The response encoding mirrors nex-protocols-common-go v2.6.1
// matchmake_extension.browseMatchmakeSession.
func browseMatchmakeSessionStable(mm *common_globals.MatchmakingManager, wildcardIdx []int) func(error, nex.PacketInterface, uint32, match_making_types.MatchmakeSessionSearchCriteria, types.ResultRange) (*nex.RMCMessage, *nex.Error) {
	return func(err error, packet nex.PacketInterface, callID uint32, searchCriteria match_making_types.MatchmakeSessionSearchCriteria, resultRange types.ResultRange) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			common_globals.Logger.Error(err.Error())
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, err.Error())
		}

		connection := packet.Sender().(*nex.PRUDPConnection)
		endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)
		pid := uint64(connection.PID())

		// Blank the "hider" attributes so pin/locked rooms aren't filtered out.
		for _, j := range wildcardIdx {
			if j >= 0 && j < len(searchCriteria.Attribs) {
				searchCriteria.Attribs[j] = types.String("")
			}
		}

		mm.Mutex.RLock()
		searchCriterias := []match_making_types.MatchmakeSessionSearchCriteria{searchCriteria}
		sessions, nexErr := mmext_database.FindMatchmakeSessionBySearchCriteria(mm, connection, searchCriterias, resultRange, nil, false)
		if nexErr != nil {
			mm.Mutex.RUnlock()
			return nil, nexErr
		}
		mm.Mutex.RUnlock()

		// Stable, unique order by gathering ID, so consecutive browses are
		// identical and no room is ever listed twice.
		sort.SliceStable(sessions, func(a, b int) bool {
			return uint32(sessions[a].Gathering.ID) < uint32(sessions[b].Gathering.ID)
		})
		seen := make(map[uint32]bool, len(sessions))
		deduped := sessions[:0]
		for _, s := range sessions {
			id := uint32(s.Gathering.ID)
			if seen[id] {
				continue
			}
			seen[id] = true
			deduped = append(deduped, s)
		}
		sessions = deduped

		lstGathering := types.NewList[match_making_types.GatheringHolder]()
		for _, session := range sessions {
			// Scrub secrets, exactly as the common handler does.
			session.SessionKey = make([]byte, 0)
			session.UserPassword = ""

			holder := match_making_types.NewGatheringHolder()
			holder.Object = session.Copy().(match_making_types.GatheringInterface)
			lstGathering = append(lstGathering, holder)
		}
		logf("BROWSE caller=%d returned=%d", pid, len(sessions))

		rmcResponseStream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		lstGathering.WriteTo(rmcResponseStream)

		rmcResponse := nex.NewRMCSuccess(endpoint, rmcResponseStream.Bytes())
		rmcResponse.ProtocolID = matchmake_extension.ProtocolID
		rmcResponse.MethodID = matchmake_extension.MethodBrowseMatchmakeSession
		rmcResponse.CallID = callID
		return rmcResponse, nil
	}
}
