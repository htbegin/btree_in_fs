objs := tree.o balloc.o

.PHONY : ALL
ALL : tree

tree : $(objs) makefile
	gcc -g -o $@ $(objs)

%.o : %.c
	gcc -g -c -o $@ $<

.PHONY : clean
clean :
	rm -f $(objs) tree
