CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LIBS = -lxdp -lbpf -pthread

# Common object files
COMMON_OBJS = bitw_common.o

# Program targets
PROGRAMS = bitw_sflow bitw_filter

.PHONY: all clean

all: $(PROGRAMS)

# Common object file
bitw_common.o: bitw_common.cpp bitw_common.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# S-Flow program
bitw_sflow: bitw_sflow.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $< $(COMMON_OBJS) -o $@ $(LIBS)

# Filter program  
bitw_filter: bitw_filter.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $< $(COMMON_OBJS) -o $@ $(LIBS)

clean:
	rm -f $(PROGRAMS) $(COMMON_OBJS)

# Legacy compatibility - build original file
bitw_xdp: bitw_xdp.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)

install: $(PROGRAMS)
	cp $(PROGRAMS) /usr/local/bin/

.PHONY: install