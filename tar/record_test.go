package tar

import (
	"testing"

	F "github.com/IBM/fp-go/function"
	"github.com/stretchr/testify/assert"
)

func TestUpsert(t *testing.T) {
	// upsert a file
	upConfig := UpsertString("/etc/config/config.txt")
	config := upConfig("# this is some config")

	res := F.Pipe1(
		Empty,
		config,
	)

	assert.Contains(t, res, "etc/config/config.txt")
}

func TestUnion(t *testing.T) {
	a := UpsertString("a.txt")("a")
	b := UpsertString("b.txt")("b")
	c := UpsertString("c.txt")("c")
	c1 := UpsertString("c.txt")("c1")
	d := UpsertString("d.txt")("d")

	// the lists
	f1 := F.Pipe3(
		Empty,
		a,
		b,
		c,
	)
	// the lists
	f2 := F.Pipe2(
		Empty,
		c1,
		d,
	)
	// merge these lists
	f3 := Monoid.Concat(f1, f2)

	// sanity check
	exp := F.Pipe4(
		Empty,
		a,
		b,
		c1,
		d,
	)
	assert.Equal(t, exp, f3)
}
