package sqlite

import (
	"gotest.tools/assert"
	"reflect"
	"testing"
)

type aaa struct {
	f1 string
	f2 []byte
	f3 int64
}
type FieldMapEntry interface {
	FieldInfo() reflect.StructField
	ColumnName() string
}
type fieldMapEntry struct {
	fieldInfo  reflect.StructField
	columnName string
}

func (fme *fieldMapEntry) FieldInfo() reflect.StructField {
	return fme.fieldInfo
}
func (fme *fieldMapEntry) ColumnName() string {
	return fme.columnName
}

func TestMapper(t *testing.T) {
	var ty = reflect.TypeOf((*aaa)(nil))
	var te = ty.Elem()
	var arr []FieldMapEntry
	for i := 0; i < te.NumField(); i++ {
		var f = te.Field(i)
		var me = &fieldMapEntry{
			fieldInfo:  f,
			columnName: f.Name,
		}
		arr = append(arr, me)
	}
	var ee = new(aaa)
	var v = reflect.ValueOf(ee).Elem()
	for _, f := range arr {
		_ = reflect.Indirect(v).Field(f.FieldInfo().Index[0])
	}
	assert.Assert(t, te != nil)
}
