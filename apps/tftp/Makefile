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

CFLAGS=$(MEMMOD) -d+CFG_H=$(CFG) -i=. -i=../../../watcom/h -i=../../include -i=../../tcpinc -oh -ok -os -s -oa -ei -zp2 -zpw -we

tftp.exe: $(OBJS)
	wlink system dos option map option eliminate option stack=4096 name $@ file $(WLOBJS)
	
tftp.o: $*.cpp
	wpp $(CFLAGS) $<

packet.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

arp.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

eth.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

ip.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

utils.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

timer.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

udp.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

dns.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

trace.o: $(LIBDIR)/$*.cpp
	wpp $(CFLAGS) $<

ipasm.o: $(LIBDIR)/$*.asm
	wasm $(MEMMOD) $<

clean:
	rm -rf $(OBJS) *.map *.exe
