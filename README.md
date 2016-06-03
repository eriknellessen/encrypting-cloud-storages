# Welcome

This software enables you to transparently encrypt your Dropbox folder on your PC. It also supports sharing files with other Dropbox users, while still encrypting the shared data.

![Alt text](ecs-setup.png?raw=true "Overview of the involved components")

Warning: This is just proof-of-concept code and should _NOT_ be used in production environments

# Tested platforms:

* Debian Jessie (32 Bit)

# Building

To build the software, execute the following commands:

```sh
git clone https://github.com/eriknellessen/encrypting-cloud-storages
cd encrypting-cloud-storages/build
cmake ..
make install
```

# Using

## Transparent client-side encryption

### Configuring OpenSC

We need to configure OpenSC, so it chooses the right driver to communicate with our Android smartphone. To do so, add the following lines to the file `/etc/opensc/opensc.conf`:

```
card_drivers = openpgp-modified, internal;
```
```
card_driver openpgp-modified {
	# The location of the driver library
	module = /path/to/the/build/directory/lib/card-openpgp-modified.so;
}
```
```
card_atr 3b:80:80:01:01 {
	driver = "openpgp-modified";
}
```

On a 64 Bit system, you might need to change the path from
```
/path/to/the/build/directory/lib/card-openpgp-modified.so
```
to
```
/path/to/the/build/directory/lib64/card-openpgp-modified.so
```

### Setting up Dropbox

This needs to be done only once. It must be done before starting the transparent client-side encryption or Dropbox.

1. Create user Dropbox: `adduser Dropbox`
2. Install Dropbox (download *.deb from [here](https://www.dropbox.com/))
3. Start Dropbox as normal user, so the files are installed. When it asks for your e-mail, close dropbox.
4. Grant user Dropbox write access to your home directory, e.g. by executing `chmod 777 ~`
5. Execute `xhost +` (as normal user)
6. Start Dropbox (as user Dropbox)
7. Choose your home directory when asked where to place the Dropbox directory
8. Terminate Dropbox
9. Reclaim your Dropbox directory via chown
10. Remove all files in Dropbox, e.g. by executing `rm -rf ./* ./.*` inside the Dropbox directory

### Starting the transparent client-side encryption

This needs to be done before starting Dropbox.

To start the transparent client-side encryption, execute the following command:

```sh
bin/start_fuseecs.sh
```

### Starting Dropbox

This must not be done before starting the transparent client-side encryption.

To start Dropbox, first switch to the user Dropbox. Then start the program:

```sh
su Dropbox
/home/user/.dropbox-dist/dropbox-lnx.$PLATFORM-$VERSION/dropbox
```

## Sharing files

For sharing a folder, execute the following command:

```sh
bin/start_share_a_folder.sh $FOLDER $OPENPGP_FINGERPRINT
```

For example, the command could look like this:
```sh
bin/start_share_a_folder.sh /home/user/Dropbox/folder_to_share A6506F46
```

This shares the folder in a cryptographic way. Afterwards, you still have to share the folder via Dropbox.
