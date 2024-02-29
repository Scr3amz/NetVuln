PHONY: generate-structs
generate-structs:
	mkdir -p protos/gen
	protoc -I protos/proto protos/proto/vulners.proto \
	--go_out=./protos/gen  		 --go_opt=paths=source_relative \
	--go-grpc_out=./protos/gen	 --go-grpc_opt=paths=source_relative 