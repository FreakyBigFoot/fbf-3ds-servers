package nex

import (
	"fmt"
	"os"
	"sync/atomic"
)

// Experiment harness: the console rejects our CONNECT-ACK silently, so we vary
// the two unknown fields on EVERY CONNECT we answer. The console retries every
// two seconds, so one online attempt walks the whole combination space.

var ffeCombos = []struct{ Sig, Field string }{
	{"theirs", "zeros"}, {"theirs", "ours"}, {"theirs", "theirs"},
	{"ours", "zeros"}, {"ours", "ours"}, {"ours", "theirs"},
	{"empty", "zeros"}, {"empty", "ours"}, {"empty", "theirs"},
}

var ffeCounter atomic.Uint32
var ffeCurrent atomic.Value // struct{ Sig, Field string }

// ffeNextCombo advances one step. Called once per CONNECT packet handled.
func ffeNextCombo() {
	if os.Getenv("FFE_CYCLE") != "1" {
		return
	}
	n := ffeCounter.Add(1) - 1
	c := ffeCombos[int(n)%len(ffeCombos)]
	ffeCurrent.Store(c)
	fmt.Printf(">>> FFE CONNECT #%d -> combo %d/%d: signature=%s connSigField=%s\n",
		n+1, int(n)%len(ffeCombos)+1, len(ffeCombos), c.Sig, c.Field)
}

func ffeCombo() (string, string) {
	if os.Getenv("FFE_CYCLE") != "1" {
		return os.Getenv("FFE_SIG_MODE"), os.Getenv("FFE_CONNSIG_FIELD")
	}
	if v := ffeCurrent.Load(); v != nil {
		c := v.(struct{ Sig, Field string })
		return c.Sig, c.Field
	}
	return ffeCombos[0].Sig, ffeCombos[0].Field
}

func ffeSigMode() string      { s, _ := ffeCombo(); return s }
func ffeConnSigField() string { _, f := ffeCombo(); return f }
