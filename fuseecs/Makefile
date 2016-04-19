#These values are filled in by configuration.sh
MOUNTPOINT=/home/erik/Dropbox/
ENCRYPTED_DIRECTORY_ENCFS=/home/erik/.ecs/encrypted/
DECRYPTED_DIRECTORY_ENCFS=/home/erik/.ecs/decrypted/

all:
	#gcc -Wall direct_asymmetric_decryption_on_token/access_token.c direct_asymmetric_encryption/direct_rsa_encryption.c fusexmp.c gpg_operations.c fuseecs.c `pkg-config fuse --cflags --libs` -lgpgme -lgcrypt -pthread -o fuseecs -DHAVE_UTIMENSAT -DHAVE_SETXATTR
	#Using -Wl,-unresolved-symbols=ignore-in-shared-libs for libnpa, because we do not have it (and will not use it)
	#See http://stackoverflow.com/questions/11055569/linking-with-dynamic-library-with-dependencies
	gcc -Wall -I direct_asymmetric_decryption_on_token/OpenSC/ -I direct_asymmetric_decryption_on_token/OpenSC/src/ -I direct_asymmetric_decryption_on_token/OpenSC/src/tools/ -l opensc -Wl,-unresolved-symbols=ignore-in-shared-libs direct_asymmetric_decryption_on_token/OpenSC/src/tools/util.c direct_asymmetric_decryption_on_token/access_token.c direct_asymmetric_encryption/direct_rsa_encryption.c fusexmp.c gpg_operations.c fuseecs.c `pkg-config fuse --cflags --libs` -lgpgme -lgcrypt -pthread -o fuseecs -DHAVE_UTIMENSAT -DHAVE_SETXATTR

clean:
	rm -rf $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	rm fuseecs

preparations: all create_mountpoint

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
#	This should not be needed. Dropbox will access the folder with our access rights (via fuse).
#	chmod 777 $(MOUNTPOINT)

start: preparations
	./fuseecs -o allow_other $(MOUNTPOINT)

start_foreground: preparations
	./fuseecs -f -o allow_other $(MOUNTPOINT)
	
stop:
	fusermount -u $(MOUNTPOINT)
	
start_encfs: create_mountpoint
	echo "password" | encfs -f -o allow_other -v -d -s --stdinpass --standard $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)