

pam_skel_log.o: pam_skel_log.c
	gcc -fPIC -fno-stack-protector -c pam_skel_log.c

install: pam_skel_log.o
	ld -x --shared -o /lib64/security/pam_skel_log.so pam_skel_log.o

uninstall:
	rm -f /lib64/security/pam_skel_log.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c pam_skel_log.c
clean:
	rm -rf *.o
