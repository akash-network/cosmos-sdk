module cosmossdk.io/tx

go 1.19

require (
	cosmossdk.io/api v0.3.1
	cosmossdk.io/core v0.0.0-00010101000000-000000000000
	cosmossdk.io/math v1.0.0-beta.3
	github.com/cosmos/cosmos-proto v1.0.0-beta.1
	github.com/stretchr/testify v1.8.1
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/cosmos/gogoproto v1.4.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230202175211-008b39050e57 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// temporary until we tag a new go module
replace (
	cosmossdk.io/core => ../core
	cosmossdk.io/math => ../math
)
