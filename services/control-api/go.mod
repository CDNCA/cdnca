module github.com/cdnca/cdnca/services/control-api

go 1.27.0

toolchain go1.27.3

require (
	github.com/aliyun/aliyun-oss-go-sdk v3.0.2+incompatible
	github.com/aws/aws-sdk-go-v2 v1.41.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.3
	github.com/aws/smithy-go v1.24.2
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	github.com/cdnca/cdnca/libs/entitlement v0.0.0
	github.com/cdnca/cdnca/libs/mail v0.0.0
	github.com/cdnca/cdnca/libs/marketproto v0.0.0
	github.com/cdnca/cdnca/libs/mtlstunnel v0.0.0
	github.com/cdnca/cdnca/libs/rulepack v0.0.0
	github.com/cdnca/cdnca/libs/sitetheme v0.0.0
	github.com/cdnca/cdnca/libs/themepack v0.0.0
	github.com/cdnca/cdnca/proto/gen/go v0.0.0
	github.com/cloudflare/circl v1.6.1
	github.com/golang-jwt/jwt/v5 v5.2.3
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.5
	github.com/klauspost/compress v1.18.0
	github.com/nats-io/nats.go v1.47.0
	github.com/redis/go-redis/v9 v9.12.1
	github.com/tencentyun/cos-go-sdk-v5 v0.7.74
	golang.org/x/crypto v0.39.0
	golang.org/x/mod v0.26.0
	golang.org/x/net v0.41.0
	golang.org/x/term v0.32.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/go-sql-driver/mysql v1.9.3
)

replace github.com/cdnca/cdnca/libs/edgeconfig => ../../libs/edgeconfig

replace github.com/cdnca/cdnca/libs/entitlement => ../../libs/entitlement

replace github.com/cdnca/cdnca/libs/rulepack => ../../libs/rulepack

replace github.com/cdnca/cdnca/libs/themepack => ../../libs/themepack

replace github.com/cdnca/cdnca/libs/sitetheme => ../../libs/sitetheme

replace github.com/cdnca/cdnca/libs/marketproto => ../../libs/marketproto

replace github.com/cdnca/cdnca/libs/mtlstunnel => ../../libs/mtlstunnel

replace github.com/cdnca/cdnca/proto/gen/go => ../../proto/gen/go

require (
	filippo.io/age v1.2.1
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.21 // indirect
	github.com/cdnca/cdnca/libs/passwordpolicy v0.0.0
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clbanning/mxj v1.8.4 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mozillazg/go-httpheader v0.2.1 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pkg/sftp v1.13.9
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0
	golang.org/x/time v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)


replace github.com/cdnca/cdnca/libs/mail => ../../libs/mail

replace github.com/cdnca/cdnca/libs/passwordpolicy => ../../libs/passwordpolicy
