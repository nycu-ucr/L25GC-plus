GO_BIN_PATH = bin
GO_SRC_PATH = NFs
C_BUILD_PATH = build
ROOT_PATH = $(shell pwd)

NF = $(GO_NF)
GO_NF = amf ausf nrf nssf pcf smf udm udr chf

NF_GO_FILES = $(shell find $(GO_SRC_PATH)/$(%) -name "*.go" ! -name "*_test.go")

# VERSION = $(shell git describe --tags)
# BUILD_TIME = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
# COMMIT_HASH = $(shell git submodule status | grep $(GO_SRC_PATH)/$(@F) | awk '{print $$(1)}' | cut -c1-8)
# COMMIT_TIME = $(shell cd $(GO_SRC_PATH)/$(@F) && git log --pretty="@%at" -1 | xargs date -u +"%Y-%m-%dT%H:%M:%SZ" -d)
# LDFLAGS = -X github.com/free5gc/util/version.VERSION=$(VERSION) \
#           -X github.com/free5gc/util/version.BUILD_TIME=$(BUILD_TIME) \
#           -X github.com/free5gc/util/version.COMMIT_HASH=$(COMMIT_HASH) \
#           -X github.com/free5gc/util/version.COMMIT_TIME=$(COMMIT_TIME)

.PHONY: $(NF) clean

.DEFAULT_GOAL: nfs

nfs: $(NF)

all: $(NF)

debug: GCFLAGS += -N -l
debug: all

$(GO_NF): % : $(GO_BIN_PATH)/%

$(GO_BIN_PATH)/%: $(NF_GO_FILES)
# $(@F): The file-within-directory part of the file name of the target.
	@echo "Start building $(@F)...."
	cd $(GO_SRC_PATH)/$(@F)/cmd && \
	CGO_ENABLED=1 go build -gcflags "$(GCFLAGS)" -ldflags "$(LDFLAGS)" -o $(ROOT_PATH)/$@ main.go

vpath %.go $(addprefix $(GO_SRC_PATH)/, $(GO_NF))

clean:
	rm -rf $(addprefix $(GO_BIN_PATH)/, $(GO_NF))