all:
	#Using -Wl,-unresolved-symbols=ignore-in-shared-libs for libnpa, because we do not have it (and will not use it)
	#See http://stackoverflow.com/questions/11055569/linking-with-dynamic-library-with-dependencies
	gcc -Wall -I OpenSC/ -I OpenSC/src/ -I OpenSC/src/tools/ -l opensc -Wl,-unresolved-symbols=ignore-in-shared-libs -o access_token OpenSC/src/tools/util.c access_token.c
	gcc -Wall -I OpenSC/src/ -l opensc -shared -fPIC -DPIC -o card-openpgp-modified.so OpenSC/src/libopensc/asn1.c OpenSC/src/libopensc/sc.c OpenSC/src/libopensc/card.c OpenSC/src/libopensc/card-openpgp.c card-openpgp-modified.c
	#gcc -I OpenSC/src/ -l opensc -shared -fPIC -DPIC -o card-openpgp-modified.so OpenSC/src/libopensc/card.c card-openpgp-modified.c

preparations:
	git submodule init
	git submodule update
	cd OpenSC ;\
	autoreconf --verbose --install ;\
	./configure ;\
	cd - ;\