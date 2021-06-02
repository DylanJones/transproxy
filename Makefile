CXX = g++
CXXFLAGS = -O3 -Wall `pkg-config --cflags python3`

all:
	$(CXX) $(CXXFLAGS) transproxy.cpp -shared -o transproxy_native.so

clean:
	rm transproxy_native.so
