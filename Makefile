all:
	gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp

start:
	mkdir -p mountpoint
	./fusexmp mountpoint

stop:
	fusermount -u mountpoint