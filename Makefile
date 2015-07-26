CXXFLAGS += -g3 -march=native -std=c++11 -Wno-deprecated-declarations -pthread
#CXXFLAGS += -fsanitize=address
#CXXFLAGS += -fno-default-inline
#CXXFLAGS += -O3

main: main.cc
o3: main
o3: CXXFLAGS += -O3
