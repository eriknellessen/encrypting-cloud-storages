# Welcome

This software enables you to transparently encrypt your Dropbox folder on your PC. It also supports sharing files with other Dropbox users, while still encrypting the shared data.

![Alt text](ecs-setup.png?raw=true "Overview of the involved components")

Warning: This is just proof-of-concept code and should _NOT_ be used in production environments

The associated master's thesis can be found here:
http://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2016-01/SAR-PR-2016-01_.pdf

# Tested platforms:

* Debian Jessie (32 Bit)

# Building

[![Build Status](https://gitlab.com/eriknellessen/encrypting-cloud-storages/badges/master/pipeline.svg)](https://gitlab.com/eriknellessen/encrypting-cloud-storages/-/pipelines?ref=master) [![Code Coverage](https://gitlab.com/eriknellessen/encrypting-cloud-storages/badges/master/coverage.svg)](https://gitlab.com/eriknellessen/encrypting-cloud-storages/-/pipelines?ref=master) [![Code Quality](https://img.shields.io/badge/code%20quality-download%20report-blue)](https://gitlab.com/api/v4/projects/15583766/jobs/artifacts/master/download?job=code_quality)

To build the software, execute the following commands:

```sh
git clone https://github.com/eriknellessen/encrypting-cloud-storages
cd encrypting-cloud-storages/build
cmake ..
make install
```

# Using

## Transparent client-side encryption

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

We need to share our display, so the user Dropbox can use it. We then switch to the user Dropbox and start the program:

```sh
xhost +
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
