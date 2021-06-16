CXX = gcc
CXXFLAGS = -O3 -Wall `pkg-config --cflags python3`

all:
	$(CXX) $(CXXFLAGS) transproxy.c -shared -o transproxy_native.so

clean:
	rm transproxy_native.so
