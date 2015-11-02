all:
	gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp

start:
	./fusexmp mountpoint

stop:
	fusermount -u mountpoint