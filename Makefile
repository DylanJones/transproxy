CXX = g++
CXXFLAGS = -O3 -Wall

all:
	$(CXX) $(CXXFLAGS) transproxy.cpp -o transproxy
