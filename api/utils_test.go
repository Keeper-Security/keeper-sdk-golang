package api

import (
	"gotest.tools/assert"
	"testing"
)

func TestSet(t *testing.T) {
	var s1 = MakeSet[int64]([]int64{1, 2, 3, 4, 5, 6})
	var s2 = MakeSet[int64]([]int64{3, 4, 5, 6, 7, 8})
	var s3 = s1.Copy()
	s3.Union(s2.ToArray())
	assert.Assert(t, s3.EqualTo(MakeSet[int64]([]int64{1, 2, 3, 4, 5, 6, 7, 8})))
	s3 = s1.Copy()
	s3.Difference(s2.ToArray())
	assert.Assert(t, s3.EqualTo(MakeSet[int64]([]int64{1, 2})))
	s3 = s1.Copy()
	s3.Intersect(s2.ToArray())
	assert.Assert(t, s3.EqualTo(MakeSet[int64]([]int64{3, 4, 5, 6})))
}
