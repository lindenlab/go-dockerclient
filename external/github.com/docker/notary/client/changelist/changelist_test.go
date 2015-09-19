package changelist

import (
	"testing"

	"github.com/fsouza/go-dockerclient/external/github.com/stretchr/testify/assert"
)

func TestMemChangelist(t *testing.T) {
	cl := memChangelist{}

	c := NewTufChange(ActionCreate, "targets", "target", "test/targ", []byte{1})

	err := cl.Add(c)
	assert.Nil(t, err, "Non-nil error while adding change")

	cs := cl.List()

	assert.Equal(t, 1, len(cs), "List should have returned exactly one item")
	assert.Equal(t, c.Action(), cs[0].Action(), "Action mismatch")
	assert.Equal(t, c.Scope(), cs[0].Scope(), "Scope mismatch")
	assert.Equal(t, c.Type(), cs[0].Type(), "Type mismatch")
	assert.Equal(t, c.Path(), cs[0].Path(), "Path mismatch")
	assert.Equal(t, c.Content(), cs[0].Content(), "Content mismatch")

	err = cl.Clear("")
	assert.Nil(t, err, "Non-nil error while clearing")

	cs = cl.List()
	assert.Equal(t, 0, len(cs), "List should be empty")
}

func TestMemChangeIterator(t *testing.T) {
	cl := memChangelist{}
	it, err := cl.NewIterator()
	assert.Nil(t, err, "Non-nil error from NewIterator")
	assert.False(t, it.HasNext(), "HasNext returns false for empty ChangeList")

	c1 := NewTufChange(ActionCreate, "t1", "target1", "test/targ1", []byte{1})
	cl.Add(c1)

	c2 := NewTufChange(ActionUpdate, "t2", "target2", "test/targ2", []byte{2})
	cl.Add(c2)

	c3 := NewTufChange(ActionUpdate, "t3", "target3", "test/targ3", []byte{3})
	cl.Add(c3)

	cs := cl.List()
	index := 0
	it, _ = cl.NewIterator()
	for it.HasNext() {
		c, err := it.Next()
		assert.Nil(t, err, "Next err should be false")
		assert.Equal(t, c.Action(), cs[index].Action(), "Action mismatch")
		assert.Equal(t, c.Scope(), cs[index].Scope(), "Scope mismatch")
		assert.Equal(t, c.Type(), cs[index].Type(), "Type mismatch")
		assert.Equal(t, c.Path(), cs[index].Path(), "Path mismatch")
		assert.Equal(t, c.Content(), cs[index].Content(), "Content mismatch")
		index++
	}
	assert.Equal(t, index, len(cs), "Iterator produced all data in ChangeList")
	_, err = it.Next()
	assert.NotNil(t, err, "Next errors gracefully when exhausted")
	var iterError IteratorBoundsError
	assert.IsType(t, iterError, err, "IteratorBoundsError type")
}
