objs := tree.o balloc.o

.PHONY : ALL
ALL : tree

tree : $(objs) makefile
	gcc -pg -o $@ $(objs)

%.o : %.c
	gcc -pg -c -o $@ $<

.PHONY : clean
clean :
	rm -f $(objs) tree
