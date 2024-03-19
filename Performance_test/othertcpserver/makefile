all:io_uring reactor

io_uring:io_uring.c
	gcc -o $@ $^ -luring -static

reactor:reactor.c
	gcc -o $@ $^ 

.PHONY:clean
clean:
	rm -rf io_uring reactor