module github.com/keeper-security/keeper-sdk-golang

go 1.23.0

toolchain go1.24.5

require (
	github.com/jmoiron/sqlx v1.4.0
	github.com/mattn/go-sqlite3 v1.14.30
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.40.0
	golang.org/x/net v0.42.0
	google.golang.org/protobuf v1.36.6
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

retract [v0.9.0-alpha, v0.9.0]
