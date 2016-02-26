MOUNTPOINT=/home/destroyer/Dropbox
ENCRYPTED_DIRECTORY_ENCFS=/home/destroyer/.ecs/encrypted
DECRYPTED_DIRECTORY_ENCFS=/home/destroyer/.ecs/decrypted

all:
	gcc -Wall fusexmp.c gpg_operations.c fuseecs.c `pkg-config fuse --cflags --libs` -lgpgme -o fuseecs

clean:
	rm -rf $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	rm fuseecs

preparations: all create_mountpoint

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	chmod 777 $(MOUNTPOINT)

start: preparations
	./fuseecs -o allow_other -o debug $(MOUNTPOINT)

start_foreground: preparations
	./fuseecs -f -o allow_other -o debug $(MOUNTPOINT)
	
stop:
	fusermount -u $(MOUNTPOINT)
	
start_encfs: create_mountpoint
	echo "password" | encfs -f -o allow_other -v -d -s --stdinpass --standard $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)