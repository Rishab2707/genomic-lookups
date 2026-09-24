CXX = g++
CXXFLAGS = -O3 -std=c++20 -Wall -Wno-ignored-attributes -maes -msse4.1 -pthread
LDFLAGS = -lboost_system -lboost_thread -lpthread

all: server client dealer

server: prg.cpp dpf.cpp server.cpp
	$(CXX) $(CXXFLAGS) prg.cpp dpf.cpp server.cpp -o server $(LDFLAGS)

client: prg.cpp client.cpp
	$(CXX) $(CXXFLAGS) prg.cpp client.cpp -o client $(LDFLAGS)

dealer: prg.cpp dpf.cpp dealer.cpp
	$(CXX) $(CXXFLAGS) prg.cpp dpf.cpp dealer.cpp -o dealer $(LDFLAGS)

clean:
	rm -f server client dealer


