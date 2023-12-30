package sqlite

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"go.uber.org/zap"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

type SqlDataType uint32

func (sdt SqlDataType) ToSqlType() string {
	switch sdt {
	case SqlDataType_Integer:
		return "INTEGER"
	case SqlDataType_Numeric:
		return "REAL"
	case SqlDataType_String:
		return "TEXT"
	case SqlDataType_Blob:
		return "BLOB"
	default:
		return "TEXT"
	}
}

const (
	SqlDataType_Integer = iota + 1
	SqlDataType_Numeric
	SqlDataType_String
	SqlDataType_Blob
)

var (
	_ IColumnSchema               = &columnSchema{}
	_ ITableSchema                = &tableSchema{}
	_ ISqliteStorage[interface{}] = &sqliteStorage[interface{}]{}
)

type IColumnSchema interface {
	ColumnName() string
	ColumnSqlType() SqlDataType
}

type ITableSchema interface {
	TableName() string
	SetTableName(string)
	OwnerColumn() IColumnSchema
	Columns() []IColumnSchema
	PrimaryKey() []string
	Indexes() map[string][]string
	NewEntity() interface{}
	GetColumnByName(string) IColumnSchema
}
type columnSchema struct {
	columnName    string
	columnSqlType SqlDataType
}

func (cs *columnSchema) ColumnName() string {
	return cs.columnName
}
func (cs *columnSchema) ColumnSqlType() SqlDataType {
	return cs.columnSqlType
}

type tableSchema struct {
	tableName    string
	structType   reflect.Type
	columns      []*columnSchema
	primaryKey   []string
	indexes      map[string][]string
	ownerColumn  *columnSchema
	columnLookup map[string]*columnSchema
}

func (ts *tableSchema) createLookup() {
	if ts.columnLookup == nil {
		ts.columnLookup = make(map[string]*columnSchema)
		for _, x := range ts.columns {
			ts.columnLookup[strings.ToLower(x.ColumnName())] = x
		}
	}
}
func (ts *tableSchema) GetColumnByName(columnName string) IColumnSchema {
	ts.createLookup()
	var cs, _ = ts.columnLookup[strings.ToLower(columnName)]
	return cs
}

func (ts *tableSchema) TableName() string {
	return ts.tableName
}
func (ts *tableSchema) SetTableName(tableName string) {
	ts.tableName = tableName
}
func (ts *tableSchema) OwnerColumn() IColumnSchema {
	if ts.ownerColumn == nil {
		return nil
	}
	return ts.ownerColumn
}
func (ts *tableSchema) Columns() []IColumnSchema {
	var cols []IColumnSchema
	for _, x := range ts.columns {
		cols = append(cols, x)
	}
	return cols
}
func (ts *tableSchema) PrimaryKey() []string {
	return ts.primaryKey[:]
}
func (ts *tableSchema) Indexes() map[string][]string {
	var ids = make(map[string][]string)
	for k, v := range ts.indexes {
		ids[k] = v[:]
	}
	return ids
}
func (ts *tableSchema) NewEntity() interface{} {
	return reflect.New(ts.structType).Interface()
}

func LoadTableSchema(entityType reflect.Type, primaryKey []string, indexes map[string][]string,
	ownerColumn string, ownerType SqlDataType) (schema ITableSchema, err error) {
	if entityType.Kind() != reflect.Ptr {
		err = api.NewKeeperError(fmt.Sprintf("%s: pointer to struct expected", entityType.Name()))
		return
	}
	if entityType.Elem().Kind() != reflect.Struct {
		err = api.NewKeeperError(fmt.Sprintf("%s: pointer to struct expected", entityType.Name()))
		return
	}

	entityType = entityType.Elem()

	var columns []*columnSchema
	if columns, err = loadStructFields(entityType); err != nil {
		return
	}
	if len(columns) == 0 {
		err = api.NewKeeperError(fmt.Sprintf("\"%s\" type: does not have \"db\" tags", entityType.Name()))
		return
	}

	var pk []string
	for _, pkc := range primaryKey {
		var column *columnSchema
		for _, c := range columns {
			if c.columnName == pkc {
				column = c
				break
			}
		}
		if column == nil {
			err = api.NewKeeperError(fmt.Sprintf("Primary key column \"%s\" does not exist in \"%s\" type", pkc, entityType.Name()))
			return
		}
		pk = append(pk, column.columnName)
	}
	var idx map[string][]string
	if indexes != nil {
		idx = make(map[string][]string)
		for k, v := range indexes {
			var cols []string
			for _, ic := range v {
				var column *columnSchema
				for _, c := range columns {
					if c.columnName == ic {
						column = c
						break
					}
				}
				if column == nil {
					err = api.NewKeeperError(fmt.Sprintf("Index column \"%s\" does not exist in \"%s\" type", ic, entityType.Name()))
					return
				}
				cols = append(cols, column.columnName)
			}
			idx[k] = cols
		}
	}

	var tableName = entityType.Name()
	var rs = []rune(tableName)
	if unicode.IsLower(rs[0]) {
		rs[0] = unicode.ToUpper(rs[0])
		tableName = string(rs)
	}
	var oc *columnSchema
	if ownerColumn != "" {
		oc = &columnSchema{
			columnName:    ownerColumn,
			columnSqlType: ownerType,
		}
	}

	schema = &tableSchema{
		tableName:   tableName,
		structType:  entityType,
		columns:     columns,
		primaryKey:  pk,
		indexes:     idx,
		ownerColumn: oc,
	}
	return
}

func loadStructFields(entityType reflect.Type) (fields []*columnSchema, err error) {
	if entityType.Kind() != reflect.Struct {
		err = api.NewKeeperError(fmt.Sprintf("%s: pointer to struct expected", entityType.Name()))
		return
	}
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		tag := field.Tag.Get("db")
		if tag != "" {
			props := strings.Split(tag, ",")
			if len(props) > 0 {
				var sqlDataType SqlDataType
				if sqlDataType, _, err = getSqlDataType(field.Type); err != nil {
					fields = nil
					return
				}
				fields = append(fields, &columnSchema{
					columnName:    props[0],
					columnSqlType: sqlDataType,
				})
			}
		}
	}
	return
}

var sqlNullInt64Type = reflect.TypeOf((*sql.NullInt64)(nil)).Elem()
var sqlNullInt32Type = reflect.TypeOf((*sql.NullInt32)(nil)).Elem()
var sqlNullStringType = reflect.TypeOf((*sql.NullString)(nil)).Elem()
var sqlNullBoolType = reflect.TypeOf((*sql.NullBool)(nil)).Elem()
var sqlNullFloatType = reflect.TypeOf((*sql.NullFloat64)(nil)).Elem()

func getSqlDataType(t reflect.Type) (sqlDataType SqlDataType, nullable bool, err error) {
	switch t.Kind() {
	case reflect.Bool, reflect.Uint8, reflect.Int8:
	case reflect.Uint16, reflect.Int16:
	case reflect.Int32, reflect.Uint32:
	case reflect.Int, reflect.Uint:
	case reflect.Int64, reflect.Uint64:
		sqlDataType = SqlDataType_Integer
	case reflect.Float32, reflect.Float64:
		sqlDataType = SqlDataType_Numeric
	case reflect.String:
		nullable = true
		sqlDataType = SqlDataType_String
	case reflect.Slice:
		{
			if t.Elem().Kind() == reflect.Uint8 {
				sqlDataType = SqlDataType_Blob
			} else {
				err = api.NewKeeperError(fmt.Sprintf("field %s: only []byte are supported", t.Name()))
				return
			}
		}
	case reflect.Struct:
		{
			nullable = true
			switch t {
			case sqlNullInt64Type, sqlNullInt32Type, sqlNullBoolType:
				sqlDataType = SqlDataType_Integer
			case sqlNullStringType:
				sqlDataType = SqlDataType_String
			case sqlNullFloatType:
				sqlDataType = SqlDataType_Numeric
			default:
				err = api.NewKeeperError(fmt.Sprintf("field %s: unsupported type", t.Name()))
			}
		}
	default:
		err = api.NewKeeperError(fmt.Sprintf("field %s: unsupported type", t.Name()))
	}

	return
}

func getAllTables(connection *sqlx.DB) (tables []string, err error) {
	var rows *sqlx.Rows
	if rows, err = connection.Queryx("SELECT name FROM sqlite_master where type='table'"); err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var name string
	for rows.Next() {
		if err = rows.Scan(&name); err == nil {
			tables = append(tables, name)
		} else {
			break
		}
	}
	_ = rows.Close()
	return
}

func getAllColumns(connection *sqlx.DB, tableName string) (columns []IColumnSchema, err error) {
	var rows *sqlx.Rows
	if rows, err = connection.Queryx(fmt.Sprintf("PRAGMA table_info('%s')", tableName)); err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var ok bool
	for rows.Next() {
		var cols []interface{}
		if cols, err = rows.SliceScan(); err != nil {
			return
		}
		var colName string
		if colName, ok = cols[1].(string); !ok {
			continue
		}

		var colType string
		if colType, ok = cols[2].(string); !ok {
			continue
		}
		var sqlType SqlDataType = SqlDataType_String
		switch colType {
		case "INTEGER":
			sqlType = SqlDataType_Integer
		case "REAL":
			sqlType = SqlDataType_Numeric
		case "BLOB":
			sqlType = SqlDataType_Blob
		}
		columns = append(columns, &columnSchema{
			columnName:    colName,
			columnSqlType: sqlType,
		})
	}
	return
}

func getAllIndexes(connection *sqlx.DB, tableName string) (indexes []string, err error) {
	var rows *sqlx.Rows
	if rows, err = connection.Queryx(fmt.Sprintf("PRAGMA index_list('%s')", tableName)); err != nil {
		return
	}
	defer func() { _ = rows.Close() }()

	var ok bool
	var idxName string
	for rows.Next() {
		var idx []interface{}
		if idx, err = rows.SliceScan(); err != nil {
			return
		}
		if idxName, ok = idx[1].(string); !ok {
			continue
		}
		indexes = append(indexes, idxName)
	}
	return
}

func VerifyDatabase(connection *sqlx.DB, tables []ITableSchema, applyChanges bool) (result []string, err error) {
	var list []string
	if list, err = getAllTables(connection); err != nil {
		return
	}
	var name string
	var existingTables = make(map[string]bool)
	for _, x := range list {
		existingTables[strings.ToLower(x)] = true
	}
	var ok bool
	var table ITableSchema
	var columns []IColumnSchema
	var columnType SqlDataType
	var queries []string
	for _, table = range tables {
		name = strings.ToLower(table.TableName())
		if _, ok = existingTables[name]; ok {
			var allColumns = make(map[string]SqlDataType)
			if columns, err = getAllColumns(connection, table.TableName()); err != nil {
				return
			}
			for _, c := range columns {
				allColumns[strings.ToLower(c.ColumnName())] = c.ColumnSqlType()
			}
			if table.OwnerColumn() != nil {
				name = strings.ToLower(table.OwnerColumn().ColumnName())
				if _, ok = allColumns[name]; !ok {
					err = api.NewKeeperError(fmt.Sprintf("Table \"%s\" does not have owner column \"%s\"",
						table.TableName(), table.OwnerColumn().ColumnName()))
					return
				}
				delete(allColumns, name)
			}
			for _, x := range table.PrimaryKey() {
				name = strings.ToLower(x)
				if _, ok = allColumns[name]; !ok {
					err = api.NewKeeperError(fmt.Sprintf("Table \"%s\" does not have primary key column \"%s\"",
						table.TableName(), table.OwnerColumn().ColumnName()))
					return
				}
			}
			for _, x := range table.Columns() {
				name = strings.ToLower(x.ColumnName())
				if _, ok = allColumns[name]; !ok {
					var query = fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s",
						table.TableName(), x.ColumnName(), x.ColumnSqlType().ToSqlType())
					queries = append(queries, query)
				}
			}

			var indexes []string
			if indexes, err = getAllIndexes(connection, table.TableName()); err != nil {
				return
			}
			for indexName, indexColumns := range table.Indexes() {
				ok = false
				for _, x := range indexes {
					if strings.EqualFold(x, indexName) {
						ok = true
						break
					}
				}
				if !ok {
					var query = fmt.Sprintf("CREATE INDEX %s_%s_IDX ON %s (%s)",
						table.TableName(), indexName, table.TableName(), strings.Join(indexColumns, ", "))
					queries = append(queries, query)
				}
			}
		} else {
			var tableColumnDDL []string
			var pks []string
			if table.OwnerColumn() != nil {
				name = table.OwnerColumn().ColumnName()
				var sqlType = table.OwnerColumn().ColumnSqlType().ToSqlType()
				tableColumnDDL = append(tableColumnDDL, fmt.Sprintf("%s %s NOT NULL", name, sqlType))
				pks = append(pks, name)
			}
			var allColumns = make(map[string]SqlDataType)
			for _, c := range table.Columns() {
				allColumns[strings.ToLower(c.ColumnName())] = c.ColumnSqlType()
			}
			for _, name = range table.PrimaryKey() {
				var lName = strings.ToLower(name)
				if columnType, ok = allColumns[lName]; ok {
					tableColumnDDL = append(tableColumnDDL, fmt.Sprintf("%s %s NOT NULL", name, columnType.ToSqlType()))
					delete(allColumns, lName)
				}
				pks = append(pks, name)
			}
			for _, x := range table.Indexes() {
				for _, name = range x {
					var lName = strings.ToLower(name)
					if columnType, ok = allColumns[lName]; ok {
						tableColumnDDL = append(tableColumnDDL, fmt.Sprintf("%s %s NOT NULL", name, columnType.ToSqlType()))
						delete(allColumns, lName)
					}
				}
			}
			for _, c := range table.Columns() {
				var lName = strings.ToLower(c.ColumnName())
				if _, ok = allColumns[lName]; ok {
					tableColumnDDL = append(tableColumnDDL, fmt.Sprintf("%s %s",
						c.ColumnName(), c.ColumnSqlType().ToSqlType()))
					delete(allColumns, lName)
				}
			}
			var query = fmt.Sprintf("CREATE TABLE %s (\n%s,\nPRIMARY KEY (%s)\n)",
				table.TableName(), strings.Join(tableColumnDDL, ",\n"), strings.Join(pks, ", "))
			queries = append(queries, query)
			for indexName, indexColumns := range table.Indexes() {
				query = fmt.Sprintf("CREATE INDEX %s_%s_IDX ON %s (%s)",
					table.TableName(), indexName, table.TableName(), strings.Join(indexColumns, ", "))
				queries = append(queries, query)
			}
		}
	}
	if applyChanges {
		var txn *sqlx.Tx
		if txn, err = connection.Beginx(); err != nil {
			return
		}
		var logger = api.GetLogger()
		for _, query := range queries {
			if _, err = txn.Exec(query); err != nil {
				logger.Warn("Apply database changes error", zap.Error(err))
			} else {
				logger.Debug("Run DDL query", zap.String("query", query))
			}
		}
		err = txn.Commit()
	} else {
		result = queries
	}
	return
}

type ISqliteStorage[T any] interface {
	SelectAll(func(T) bool) error
	SelectFilter([]string, [][]interface{}, func(T) bool) error
	Put([]T) error
	DeleteAll() error
	DeleteFilter([]string, [][]interface{}) error
}

type sqliteStorage[T any] struct {
	getConnection ConnectionGetter
	schema        ITableSchema
	ownerValue    interface{}
	queryCache    map[string]string
}

func (ss *sqliteStorage[T]) filterColumns(columns []string) (tag string, err error) {
	var cols = make(map[string]bool)
	var ok bool
	for _, x := range columns {
		var cs = ss.schema.GetColumnByName(x)
		if cs == nil {
			err = api.NewKeeperError(
				fmt.Sprintf("Table %s: Column %s not found", ss.schema.OwnerColumn(), x))
			return
		}
		if _, ok = cols[cs.ColumnName()]; ok {
			err = api.NewKeeperError(fmt.Sprintf("Filter multiple criterias for column %s", cs.ColumnName()))
			return
		}
		cols[cs.ColumnName()] = true
	}
	var filteredColumns []string
	for k := range cols {
		filteredColumns = append(filteredColumns, k)
	}
	sort.Slice(filteredColumns, func(i, j int) bool {
		return filteredColumns[i] < filteredColumns[j]
	})
	tag = strings.Join(filteredColumns, ",")
	return
}

func (ss *sqliteStorage[T]) Schema() ITableSchema {
	return ss.schema
}

func (ss *sqliteStorage[T]) SelectAll(cb func(T) bool) (err error) {
	var key = "select-all"
	var ok bool
	var query string
	if query, ok = ss.queryCache[key]; !ok {
		var columns []string
		for _, x := range ss.schema.Columns() {
			columns = append(columns, x.ColumnName())
		}
		query = fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), ss.schema.TableName())
		if ss.schema.OwnerColumn() != nil {
			query += fmt.Sprintf(" WHERE %s = ?", ss.schema.OwnerColumn().ColumnName())
		}
		ss.queryCache[key] = query
	}

	var txn *sqlx.Tx
	if txn, err = ss.getConnection().Beginx(); err != nil {
		return
	}
	defer func() { _ = txn.Commit() }()

	var rows *sqlx.Rows
	var args []interface{}
	if ss.schema.OwnerColumn() != nil {
		args = append(args, ss.ownerValue)
	}
	if rows, err = txn.Queryx(query, args...); err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var e T
	for rows.Next() {
		var intf = ss.schema.NewEntity()
		if err = rows.StructScan(intf); err != nil {
			return
		}
		if e, ok = intf.(T); ok {
			if !cb(e) {
				break
			}
		}
	}
	return
}

func (ss *sqliteStorage[T]) SelectFilter(filterColumns []string, filterValues [][]interface{}, cb func(T) bool) (err error) {
	var key string
	if key, err = ss.filterColumns(filterColumns); err != nil {
		return
	}
	key = fmt.Sprintf("select-filter: %s", key)
	var ok bool
	var query string
	if query, ok = ss.queryCache[key]; !ok {
		var columns []string
		for _, x := range ss.schema.Columns() {
			columns = append(columns, x.ColumnName())
		}
		query = fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), ss.schema.TableName())
		columns = nil
		if ss.schema.OwnerColumn() != nil {
			var ownerName = ss.schema.OwnerColumn().ColumnName()
			columns = append(columns, fmt.Sprintf("%s = ?", ownerName))
		}
		for _, x := range filterColumns {
			columns = append(columns, fmt.Sprintf("%s = ?", x))
		}
		if len(columns) > 0 {
			query += fmt.Sprintf(" WHERE %s", strings.Join(columns, " AND "))
		}
		ss.queryCache[key] = query
	}

	var txn *sqlx.Tx
	if txn, err = ss.getConnection().Beginx(); err != nil {
		return
	}
	defer func() { _ = txn.Commit() }()
	var stmt *sqlx.Stmt
	if stmt, err = txn.Preparex(query); err != nil {
		return
	}
	defer func() { _ = stmt.Close() }()
	for _, fv := range filterValues {
		var args []interface{}
		if ss.schema.OwnerColumn() != nil {
			args = append(args, ss.ownerValue)
		}
		args = append(args, fv...)
		var rows *sqlx.Rows
		if rows, err = stmt.Queryx(args...); err != nil {
			break
		}
		var e T
		for rows.Next() {
			var intf = ss.schema.NewEntity()
			if err = rows.StructScan(intf); err == nil {
				if e, ok = intf.(T); ok {
					if !cb(e) {
						break
					}
				}
			} else {
				break
			}
		}
		_ = rows.Close()
		if err != nil {
			break
		}
	}
	return
}

func (ss *sqliteStorage[T]) Put(rows []T) (err error) {
	var key = "put"
	var ok bool
	var query string
	if query, ok = ss.queryCache[key]; !ok {
		var columns []string
		var values []string
		if ss.schema.OwnerColumn() != nil {
			var ownerColumn = ss.schema.OwnerColumn().ColumnName()
			columns = append(columns, ownerColumn)
			values = append(values, ":"+ownerColumn)
		}
		for _, x := range ss.schema.Columns() {
			columns = append(columns, x.ColumnName())
			values = append(values, ":"+x.ColumnName())
		}
		query = fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)",
			ss.schema.TableName(), strings.Join(columns, ", "), strings.Join(values, ", "))
		ss.queryCache[key] = query
	}
	var txn *sqlx.Tx
	if txn, err = ss.getConnection().Beginx(); err != nil {
		return
	}
	defer func() { _ = txn.Commit() }()

	var stmt *sqlx.NamedStmt
	if stmt, err = txn.PrepareNamed(query); err != nil {
		return
	}
	defer func() { _ = stmt.Close() }()
	for _, row := range rows {
		var m = make(map[string]interface{})
		if ss.schema.OwnerColumn() != nil {
			m[ss.schema.OwnerColumn().ColumnName()] = ss.ownerValue
		}
		var v reflect.Value
		for v = reflect.ValueOf(row); v.Kind() == reflect.Ptr; {
			v = v.Elem()
		}
		_ = stmt.Stmt.Mapper.TraversalsByNameFunc(v.Type(), stmt.Params, func(i int, ints []int) error {
			if len(ints) > 0 {
				val := reflectx.FieldByIndexesReadOnly(v, ints)
				m[stmt.Params[i]] = val.Interface()
			}
			return nil
		})
		if _, err = stmt.Exec(m); err != nil {
			return
		}
	}
	return
}

func (ss *sqliteStorage[T]) DeleteAll() (err error) {
	var key = "delete: all"
	var ok bool
	var query string
	if query, ok = ss.queryCache[key]; !ok {
		query = fmt.Sprintf("DELETE FROM %s", ss.schema.TableName())
		if ss.schema.OwnerColumn() != nil {
			var ownerName = ss.schema.OwnerColumn().ColumnName()
			query += fmt.Sprintf(" WHERE %s = ?", ownerName)
		} else {
			query += " WHERE 1=1"
		}
		ss.queryCache[key] = query
	}
	var txn *sqlx.Tx
	if txn, err = ss.getConnection().Beginx(); err != nil {
		return
	}
	var args []interface{}
	if ss.schema.OwnerColumn() != nil {
		args = append(args, ss.ownerValue)
	}
	_, err = txn.Exec(query, args...)
	_ = txn.Commit()
	return
}

func (ss *sqliteStorage[T]) DeleteFilter(filterColumns []string, filterValues [][]interface{}) (err error) {
	var key string
	if key, err = ss.filterColumns(filterColumns); err != nil {
		return
	}
	key = fmt.Sprintf("delete: %s", key)
	var ok bool
	var query string
	if query, ok = ss.queryCache[key]; !ok {
		query = fmt.Sprintf("DELETE FROM %s", ss.schema.TableName())
		var columns []string
		if ss.schema.OwnerColumn() != nil {
			var ownerName = ss.schema.OwnerColumn().ColumnName()
			columns = append(columns, fmt.Sprintf("%s = ?", ownerName))
		}
		for _, x := range filterColumns {
			columns = append(columns, fmt.Sprintf("%s = ?", x))
		}
		query += fmt.Sprintf(" WHERE %s", strings.Join(columns, " AND "))
		ss.queryCache[key] = query
	}
	var txn *sqlx.Tx
	if txn, err = ss.getConnection().Beginx(); err != nil {
		return
	}
	defer func() { _ = txn.Commit() }()

	var stmt *sql.Stmt
	if stmt, err = txn.Prepare(query); err != nil {
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, fv := range filterValues {
		var args []interface{}
		if ss.schema.OwnerColumn() != nil {
			args = append(args, ss.ownerValue)
		}
		args = append(args, fv...)
		if _, err = stmt.Exec(args...); err != nil {
			break
		}
	}
	return
}
