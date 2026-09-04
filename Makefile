CXX = g++
CXXFLAGS = -O3 -std=c++20 -Wall -Wno-ignored-attributes -maes -msse4.1 -pthread
LDFLAGS = -lboost_system -lboost_thread -lpthread

all: server client test_leafless

server: prg.cpp dpf.cpp server.cpp
	$(CXX) $(CXXFLAGS) prg.cpp dpf.cpp server.cpp -o server $(LDFLAGS)

client: prg.cpp dpf.cpp client.cpp
	$(CXX) $(CXXFLAGS) prg.cpp dpf.cpp client.cpp -o client $(LDFLAGS)

test_leafless: prg.cpp dpf.cpp test_leafless.cpp
	$(CXX) $(CXXFLAGS) prg.cpp dpf.cpp test_leafless.cpp -o test_leafless $(LDFLAGS)

clean:
	rm -f server client test_leafless
