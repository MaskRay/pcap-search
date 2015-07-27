CXXFLAGS += -g3 -march=native -std=c++11 -Wno-deprecated-declarations -pthread

indexer: indexer.cc

debug: indexer
debug: CXXFLAGS += -fno-inline-functions -fkeep-inline-functions

asan: debug
asan: CXXFLAGS += -fsanitize=address

opt: indexer
opt: CXXFLAGS += -O3

.PHONY: debug asan opt
