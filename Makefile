all:
	gcc -Wall fusexmp.c fuseecs.c `pkg-config fuse --cflags --libs` -o fuseecs

create_mountpoint:
	mkdir -p mountpoint

start: create_mountpoint
	./fuseecs -o allow_other mountpoint

start_foreground: create_mountpoint
	./fuseecs -f -o allow_other mountpoint
stop:
	fusermount -u mountpoint