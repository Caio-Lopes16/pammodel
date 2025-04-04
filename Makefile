

pam_model.o: pam_model.c
	gcc -fPIC -fno-stack-protector -c pam_model.c

install: pam_model.o
	ld -x --shared -o /lib64/security/pam_model.so pam_model.o

uninstall:
	rm -f /lib64/security/pam_model.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c pam_model.c
clean:
	rm -rf *.o
