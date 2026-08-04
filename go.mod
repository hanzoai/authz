module github.com/hanzoai/authz

go 1.26.5

// The decision leaf (package authz) requires golang-jwt/v5 alone — the library IAM
// signs with, and itself a pure-stdlib module. The serve package, which is the
// network surface and nothing else, adds the request tier.
require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/luxfi/log v1.5.0
	github.com/zap-proto/zip v1.24.2
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	github.com/zap-proto/fiber/v3 v3.2.1 // indirect
	github.com/zap-proto/go v1.3.0 // indirect
	github.com/zap-proto/http v0.3.1 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
