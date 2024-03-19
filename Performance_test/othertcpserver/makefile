all:io_uring reactor
io_uring:io_uring.cc
	gcc -o $@ $^ -luring -static

reactor:reactor.cc
	gcc -o $@ $^ 

.PHONY:clean
clean:
	rm -rf io_uring reactor