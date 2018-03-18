objs := tree.o balloc.o

.PHONY : ALL
ALL : tree

tree : $(objs) makefile
	gcc -o $@ $(objs)

%.o : %.c
	gcc -c -o $@ $<

