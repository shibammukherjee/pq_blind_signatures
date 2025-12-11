BUILD_SCRIPT_LOCATION := ../vole/
BUILD_SCRIPT_NAME := build_consv_bs_keccak.sh
LIBRARY_FOLDER := ../vole/faest-cpp-tmp/build_debug

.PHONY: all

all:
	mkdir -p target/debug
	cd $(BUILD_SCRIPT_LOCATION) && ./$(BUILD_SCRIPT_NAME)
	cp $(LIBRARY_FOLDER)/libvolekeccak_then_mayo_bs.so target/debug