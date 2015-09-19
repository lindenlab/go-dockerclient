package memory

import (
	"testing"

	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/registry/storage/cache"
)

// TestInMemoryBlobInfoCache checks the in memory implementation is working
// correctly.
func TestInMemoryBlobInfoCache(t *testing.T) {
	cache.CheckBlobDescriptorCache(t, NewInMemoryBlobDescriptorCacheProvider())
}
