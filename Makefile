CXXFLAGS += -g3 -march=native -std=c++11 -Wno-deprecated-declarations -pthread

all: indexer indexer32

indexer: indexer.cc
indexer32: indexer.cc
	$(LINK.cc) -m32 $^ -o $@

debug: indexer
debug: CXXFLAGS += -fno-inline-functions -fkeep-inline-functions

asan: debug
asan: CXXFLAGS += -fsanitize=address

opt: indexer
opt: CXXFLAGS += -O3

.PHONY: debug asan opt
