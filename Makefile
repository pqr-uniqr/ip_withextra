CC = gcc
DEBUGFLAGS = -g -Wall -I
CFLAGS = -D_REENTRANT $(DEBUGFLAGS) -D_XOPEN_SOURCE=500
LDFLAGS = -pthread

all: node

node: node.c node.h
