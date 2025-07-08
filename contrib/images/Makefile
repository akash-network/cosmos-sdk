space:=
space+=

CURRENT_PATH := $(subst $(lastword $(notdir $(MAKEFILE_LIST))),,$(subst $(space),$(space),$(shell realpath '$(strip $(MAKEFILE_LIST))')))

GO_VERSION := $(shell grep -E '^go [0-9]{1,}.[0-9]{1,}(.[0-9]{1,})?$$' "$(CURRENT_PATH)../../go.mod" | cut -d ' ' -f 2 | tr -d '\n')

all: simd-env

simd-env: simd-rmi
	docker build --build-arg GO_VERSION="$(GO_VERSION)" --tag cosmossdk/simd -f simd-env/Dockerfile \
		$(shell git rev-parse --show-toplevel)

simd-dlv: simd-rmi
	docker build --build-arg GO_VERSION="$(GO_VERSION)" --tag cosmossdk/simd -f simd-dlv/Dockerfile \
		$(shell git rev-parse --show-toplevel)

simd-rmi:
	docker rmi cosmossdk/simd 2>/dev/null; true

.PHONY: all simd-env simd-dlv simd-rmi
