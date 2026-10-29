package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	mmt "github.com/PretendoNetwork/nex-protocols-go/v2/match-making/types"
)

// Two real CreateMatchmakeSession requests captured from consoles (RAW PARAMS in
// the server log): one from the self-hoster in GitHub issue #2 (their server ran
// the run.sh.example defaults = variant 0 / NEX 2.0.0) and one from the live
// server on 2026-10-28 (variant 6 + FFE_* overrides). Same game build, same shape.
const issue2CreateHex = "11004d617463686d616b6553657373696f6e00dc000000d800000000000000000000000000000000000400080000000000000030000000000000000100000100000006000000000000002e00000000000000000000000000000000020000000100000084000000000210275900650073000000ffffffff9827ed08e0ba01140a000000010000000000000074502800ffffffffffffffff000000008026ed080000803f0000803fa0ba011450b80000dc504c08082a5b0028b1930000000000610b363f5b882bae010004000000390000000000000000ffffffffffffff000000002e0000000000000000000000000000000000010000"
const liveCreateHex = "11004d617463686d616b6553657373696f6e00dc000000d8000000000000000000000000000000000004000800000000000000300000000000000001000001000000060000000000000015000000000000000000000000000000000200000001000000840000000002102743006c006f0075006400000028b4ed0868bb01140a000000010000000000000074502800ffffffffffffffff0000000010b3ed080000803f0000803f28bb011450b800009c3d4c08082a5b0000deed0800000000610b363f5b882bae0100040000001d0000000000000014ffffffffffffff00000000150000000000000000000000000000000000010000"

type dialect struct {
	name   string
	lib    [3]int // main library version (FFE_LIB_MAJOR/MINOR/PATCH or the variant's)
	header bool   // FFE_STRUCT_HEADER
	mm     int    // FFE_MM_MINOR (MatchMaking lib 3.<mm>.0); 0 = not set (inherits main)
}

func (d dialect) versions() (*nex.LibraryVersions, *nex.ByteStreamSettings) {
	lv := nex.NewLibraryVersions()
	lv.SetDefault(nex.NewLibraryVersion(d.lib[0], d.lib[1], d.lib[2]))
	if d.mm != 0 {
		lv.MatchMaking = nex.NewLibraryVersion(3, d.mm, 0)
	}
	bs := nex.NewByteStreamSettings()
	bs.UseStructureHeader = d.header
	return lv, bs
}

// parseCreate mirrors nex-protocols-go matchmake-extension handleCreateMatchmakeSession.
func parseCreate(d dialect, raw []byte) (summary string, err error) {
	lv, bs := d.versions()
	in := nex.NewByteStreamIn(raw, lv, bs)
	var holder mmt.GatheringHolder
	var msg types.String
	var count types.UInt16
	if err = holder.ExtractFrom(in); err != nil {
		return "", fmt.Errorf("anyGathering: %w", err)
	}
	if err = msg.ExtractFrom(in); err != nil {
		return "", fmt.Errorf("strMessage: %w", err)
	}
	if lv.MatchMaking.GreaterOrEqual("3.4.0") {
		if err = count.ExtractFrom(in); err != nil {
			return "", fmt.Errorf("participationCount: %w", err)
		}
	}
	// Round-trip: re-encode under the same dialect; a faithful decode reproduces the bytes.
	out := nex.NewByteStreamOut(lv, bs)
	holder.WriteTo(out)
	msg.WriteTo(out)
	if lv.MatchMaking.GreaterOrEqual("3.4.0") {
		count.WriteTo(out)
	}
	rt := "round-trip OK"
	if !bytes.Equal(out.Bytes(), raw) {
		rt = fmt.Sprintf("round-trip MISMATCH (re-encoded %d bytes vs %d)", len(out.Bytes()), len(raw))
	}
	ms, ok := holder.Object.(mmt.MatchmakeSession)
	if !ok {
		return fmt.Sprintf("holder=%T remaining=%d %s", holder.Object, in.Remaining(), rt), nil
	}
	return fmt.Sprintf("gid=%d owner=%d host=%d min=%d max=%d policy=%d flags=%d state=%d mode=%d attrs=%v open=%v count=%d msg=%q remaining=%d; %s",
		ms.ID, ms.OwnerPID, ms.HostPID, ms.MinimumParticipants, ms.MaximumParticipants,
		ms.ParticipationPolicy, ms.Flags, ms.State, ms.GameMode, ms.Attributes, ms.OpenParticipation, count, msg, in.Remaining(), rt), nil
}

func TestCreateMatchmakeSessionDialect(t *testing.T) {
	dialects := []dialect{
		{"run.sh.example defaults = variant 0 (NEX 2.0.0, no header, no MM override)", [3]int{2, 0, 0}, false, 0},
		{"variant 6 bare (NEX 3.6.9, header ON, no MM override)", [3]int{3, 6, 9}, true, 0},
		{"live minus FFE_MM_MINOR (NEX 3.5.0, no header, MM inherits 3.5.0)", [3]int{3, 5, 0}, false, 0},
		{"LIVE run.sh (NEX 3.5.0, no header, MM 3.3.0)", [3]int{3, 5, 0}, false, 3},
	}
	captures := map[string]string{"issue#2 console": issue2CreateHex, "live console 2026-10-28": liveCreateHex}
	for capName, h := range captures {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", capName, err)
		}
		t.Logf("==== %s (%d bytes) ====", capName, len(raw))
		for _, d := range dialects {
			s, err := parseCreate(d, raw)
			if err != nil {
				t.Logf("  [FAIL ] %-72s -> %v", d.name, err)
				continue
			}
			t.Logf("  [parse] %-72s -> %s", d.name, s)
		}
	}
	// Response side (mirrors nex-protocols-common-go create_matchmake_session.go):
	// gid, then SessionKey only when MatchMaking >= 3.0.0. The console sent a
	// SessionKey field in its request, so it expects one back; the example config
	// answers with a bare 4-byte gid and the game leaves the room on the spot.
	key := make([]byte, 32)
	for _, d := range []dialect{dialects[0], dialects[3]} {
		lv, bs := d.versions()
		out := nex.NewByteStreamOut(lv, bs)
		types.UInt32(367).WriteTo(out)
		if lv.MatchMaking.GreaterOrEqual("3.0.0") {
			types.Buffer(key).WriteTo(out)
		}
		t.Logf("  [reply] %-72s -> CreateMatchmakeSession response payload = %d bytes", d.name, len(out.Bytes()))
	}
	lvEx, bsEx := dialects[0].versions()
	outEx := nex.NewByteStreamOut(lvEx, bsEx)
	types.UInt32(367).WriteTo(outEx)
	if lvEx.MatchMaking.GreaterOrEqual("3.0.0") {
		t.Errorf("example dialect unexpectedly includes SessionKey")
	}
	if len(outEx.Bytes()) != 4 {
		t.Errorf("example dialect reply should be a bare gid (4 bytes), got %d", len(outEx.Bytes()))
	}

	// The live dialect must decode both captures exactly.
	for capName, h := range captures {
		raw, _ := hex.DecodeString(h)
		s, err := parseCreate(dialects[3], raw)
		if err != nil || !bytes.Contains([]byte(s), []byte("round-trip OK")) || !bytes.Contains([]byte(s), []byte("remaining=0")) {
			t.Errorf("live dialect failed to decode %s exactly: %v %s", capName, err, s)
		}
	}
}
