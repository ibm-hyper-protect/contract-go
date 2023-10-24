package optional

import (
	"testing"

	O "github.com/IBM/fp-go/option"
	T "github.com/ibm-hyper-protect/contract-go/tar"
	"github.com/stretchr/testify/assert"
)

func TestOptionalString(t *testing.T) {
	// come up with a simple file list
	files1 := T.FromEntries([]T.FileEntry{
		T.CreateEntry("test1.txt")([]byte("test1")),
		T.CreateEntry("test2.txt")([]byte("test2")),
	})
	// try to access and modify
	optTest2 := String("test2.txt")

	assert.Equal(t, O.Of("test2"), optTest2.GetOption(files1))

	files2 := optTest2.Set("test2a")(files1)
	assert.NotEqual(t, files1, files2)

	assert.Equal(t, O.Of("test2"), optTest2.GetOption(files1))
	assert.Equal(t, O.Of("test2a"), optTest2.GetOption(files2))

	// try to access non existing value
	optTest3 := String("test3.txt")
	assert.Equal(t, O.None[string](), optTest3.GetOption(files1))
	assert.Equal(t, O.None[string](), optTest3.GetOption(files2))
}

func TestOptionalBytes(t *testing.T) {
	// come up with a simple file list
	files1 := T.FromEntries([]T.FileEntry{
		T.CreateEntry("test1.txt")([]byte("test1")),
		T.CreateEntry("test2.txt")([]byte("test2")),
	})
	// try to access and modify
	optTest2 := Bytes("test2.txt")

	assert.Equal(t, O.Of([]byte("test2")), optTest2.GetOption(files1))

	files2 := optTest2.Set([]byte("test2a"))(files1)
	assert.NotEqual(t, files1, files2)

	assert.Equal(t, O.Of([]byte("test2")), optTest2.GetOption(files1))
	assert.Equal(t, O.Of([]byte("test2a")), optTest2.GetOption(files2))

	// try to access non existing value
	optTest3 := String("test3.txt")
	assert.Equal(t, O.None[string](), optTest3.GetOption(files1))
	assert.Equal(t, O.None[string](), optTest3.GetOption(files2))
}
