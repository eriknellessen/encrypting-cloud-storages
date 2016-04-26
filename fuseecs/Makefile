#These values are filled in by configuration.sh
MOUNTPOINT=
ENCRYPTED_DIRECTORY_ENCFS=
DECRYPTED_DIRECTORY_ENCFS=

start_foreground: create_mountpoint
	./fuseecs -f -o allow_other $(MOUNTPOINT)

start: create_mountpoint
	./fuseecs -o allow_other $(MOUNTPOINT)

stop:
	fusermount -u $(MOUNTPOINT)
	
start_encfs: create_mountpoint
	echo "password" | encfs -f -o allow_other -v -d -s --stdinpass --standard $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	This should not be needed. Dropbox will access the folder with our access rights (via fuse).
#	chmod 777 $(MOUNTPOINT)

clean:
	rm -rf $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)