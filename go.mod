module github.com/keeper-security/keeper-sdk-golang

go 1.20

require (
	github.com/jmoiron/sqlx v1.3.5
	github.com/mattn/go-sqlite3 v1.14.19
	go.uber.org/zap v1.26.0
	golang.org/x/crypto v0.17.0
	golang.org/x/net v0.19.0
	google.golang.org/protobuf v1.32.0
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

retract (
	v0.9.0
	v0.9.0-alpha2
	v0.9.0-alpha1
	v0.9.0-alpha
)
