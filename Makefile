CXXFLAGS += -g3 -march=native -std=c++11 -Wno-deprecated-declarations -pthread

all: indexer

clean:
	$(RM) indexer

.PHONY: all clean
