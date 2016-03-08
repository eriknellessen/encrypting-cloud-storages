#These values are filled in by configuration.sh
MOUNTPOINT=
ENCRYPTED_DIRECTORY_ENCFS=
DECRYPTED_DIRECTORY_ENCFS=

all:
	gcc -Wall fusexmp.c gpg_operations.c fuseecs.c `pkg-config fuse --cflags --libs` -lgpgme -pthread -o fuseecs -DHAVE_UTIMENSAT -DHAVE_SETXATTR

clean:
	rm -rf $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	rm fuseecs

preparations: all create_mountpoint

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	chmod 777 $(MOUNTPOINT)

start: preparations
	./fuseecs -o allow_other $(MOUNTPOINT)

start_foreground: preparations
	./fuseecs -f -o allow_other $(MOUNTPOINT)
	
stop:
	fusermount -u $(MOUNTPOINT)
	
start_encfs: create_mountpoint
	echo "password" | encfs -f -o allow_other -v -d -s --stdinpass --standard $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)