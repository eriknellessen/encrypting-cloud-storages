MOUNTPOINT=/tmp/mountpoint
ENCRYPTED_DIRECTORY_ENCFS=/tmp/encrypted
DECRYPTED_DIRECTORY_ENCFS=/tmp/decrypted

all:
	gcc -Wall fusexmp.c fuseecs.c `pkg-config fuse --cflags --libs` -o fuseecs

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)

start: create_mountpoint
	./fuseecs -o allow_other -o debug $(MOUNTPOINT)

start_foreground: create_mountpoint
	./fuseecs -f -o allow_other -o debug $(MOUNTPOINT)
	
stop:
	fusermount -u $(MOUNTPOINT)
	
start_encfs: create_mountpoint
	echo "password" | encfs -f -o allow_other -v -d -s --stdinpass --standard $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)