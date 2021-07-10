#
#
#

WATCOM=$(HOME)/watcom
.export WATCOM

CFG=\"tftp.cfg\"
LIBDIR=../../tcplib

OBJS=tftp.o

OBJS+=packet.o arp.o eth.o ip.o utils.o timer.o udp.o dns.o trace.o
OBJS+=ipasm.o

WLOBJS!=echo $(OBJS) | sed 's/ /,/g'

CFLAGS=-ms -d+CFG_H=$(CFG) -i=. -i=../../../watcom/h -i=../../include -i=../../tcpinc -oh -ok -os -s -oa -ei -zp2 -zpw -we

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
	wasm -ms $<

clean:
	rm -rf $(OBJS) *.map *.exe
