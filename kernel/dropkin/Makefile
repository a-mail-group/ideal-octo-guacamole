#
# Makefile for the Dropkin LSM
#

obj-$(CONFIG_SECURITY_DROPKIN) := dropkin.o

dropkin-y := dropkin_lsm.o pledge.o mls.o

# LSM Hooks.
dropkin-y += sm_tasks.o sm_io.o sm_sysv.o sm_file.o
dropkin-$(CONFIG_SECURITY_NETWORK) += sm_socket.o

