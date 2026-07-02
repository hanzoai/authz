module github.com/hanzoai/authz

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/golang/mock v1.7.0-rc.1
	github.com/tidwall/gjson v1.18.0
	github.com/zap-proto/zip v1.1.0
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/dop251/goja v0.0.0-20260607120635-348e6bea910d // indirect
	github.com/evanw/esbuild v0.28.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/gofiber/fiber/v3 v3.2.0 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	github.com/zap-proto/go v1.3.0 // indirect
	github.com/zap-proto/http v0.1.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

// HIP-0106 unified cloud binary — Mount() entry point in pkg/authz/mount.go.
// Pinned to v0.0.0 + local replace until cloud and zip publish stable tags;
// matches the kms / vfs convention (see hanzoai/kms go.mod).
require github.com/hanzoai/cloud v0.1.0

go 1.26.4
