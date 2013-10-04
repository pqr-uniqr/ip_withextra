CC = gcc
DEBUGFLAGS = -g -Wall -I
CFLAGS = -D_REENTRANT $(DEBUGFLAGS) -D_XOPEN_SOURCE=500
LDFLAGS = -pthread

all: node.c node.h csupport/*.c
 
