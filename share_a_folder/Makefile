MOUNTPOINT=/tmp/mountpoint
ENCRYPTED_DIRECTORY_ENCFS=/tmp/encrypted
DECRYPTED_DIRECTORY_ENCFS=/tmp/decrypted

all:
	gcc -Wall share_a_folder.c -D_FILE_OFFSET_BITS=64 -lgpgme -o share_a_folder

preparations: all create_mountpoint

create_mountpoint:
	mkdir -p $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)
	chmod 777 $(MOUNTPOINT) $(ENCRYPTED_DIRECTORY_ENCFS) $(DECRYPTED_DIRECTORY_ENCFS)