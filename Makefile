

pammodel.o: pammodelfa.c
	gcc -fPIC -fno-stack-protector -c pammodelfa.c

install: pam_skel_log.o
	ld -x --shared -o /lib64/security/pammodelfa.so pammodelfa.o

uninstall:
	rm -f /lib64/security/pammodelfa.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c pammodelfa.c
clean:
	rm -rf *.o
