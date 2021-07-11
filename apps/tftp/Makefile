#
# TFTP makefile
#
# -oa   Relax alias checking
# -ob   Try to generate straight line code
# -oe - expand user functions inline (-oe=20 is default)
# -oh   Enable repeated optimizations
# -oi   generate certain lib funcs inline
# -oi+  Set max inline depth (C++ only, use -oi for C)
# -ok   Flowing of register save into function flow graph
# -ol   loop optimizations
# -ol+  loop optimizations plus unrolling
# -or   Reorder for pipelined (486+ procs); not sure if good to use
# -os   Favor space over time
# -ot   Favor time over space
# -ei   Allocate an "int" for all enum types
# -zp2  Allow compiler to add padding to structs
# -zpw  Use with above; make sure you are warning free!
# -0    8088/8086 class code generation
# -s    disable stack overflow checking
# -zmf  put each function in a new code segment; helps with linking
# For this code performance is not an issue.  Make it small.
#

WATCOM=$(HOME)/watcom
.export WATCOM

CFG=\"tftp.cfg\"
LIBDIR=../../tcplib

MEMMOD=-ms

OBJS=tftp.o

OBJS+=packet.o arp.o eth.o ip.o utils.o timer.o udp.o dns.o trace.o
OBJS+=ipasm.o

WLOBJS!=echo $(OBJS) | sed 's/ /,/g'

CFLAGS=$(MEMMOD) -d+CFG_H=$(CFG)
CFLAGS+=-i=. -i=../../../watcom/h -i=../../include -i=../../tcpinc
CFLAGS+=-oh -ok -os -s -oa -ei -zp2 -zpw -we

tftp.exe: $(OBJS)
	wlink system dos option map option eliminate option stack=4096 name $@ file $(WLOBJS)
	
.cpp.o:
	wpp $(CFLAGS) $<

tftp.o: $*.cpp

packet.o: $(LIBDIR)/$*.cpp
arp.o: $(LIBDIR)/$*.cpp
eth.o: $(LIBDIR)/$*.cpp
ip.o: $(LIBDIR)/$*.cpp
utils.o: $(LIBDIR)/$*.cpp
timer.o: $(LIBDIR)/$*.cpp
udp.o: $(LIBDIR)/$*.cpp
dns.o: $(LIBDIR)/$*.cpp
trace.o: $(LIBDIR)/$*.cpp

ipasm.o: $(LIBDIR)/$*.asm
	wasm $(MEMMOD) $<

clean:
	rm -rf $(OBJS) *.map *.exe
