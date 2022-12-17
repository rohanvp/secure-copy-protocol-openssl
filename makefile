all:ufsend.c ufrec.c
	gcc ufsend.c -o ufsend -lssl -lcrypto
	gcc ufrec.c -o ufrec -lssl -lcrypto
