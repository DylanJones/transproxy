# transproxy

If you've ever tried to set up programs to work behind a restrictive proxy, you know just how much of a pain it can be to configure each and every program to use the proxy.  `transproxy` fixes that by automatically redirecting all HTTP/HTTPS requests outside of your local network through a configurable upstream proxy.

Settings are defined in `transproxy.cfg`.  If you want to use the native code feature for increased throughput/decreased CPU time, run `make` and set `use_native` to True in the config file.
