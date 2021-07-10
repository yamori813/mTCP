/*

   mTCP tftp.cpp
   Copyright (C) 2010-2020 Michael B. Brutman (mbbrutman@gmail.com)
   mTCP web page: http://www.brutman.com/mTCP


   This file is part of mTCP.

   mTCP is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   mTCP is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with mTCP.  If not, see <http://www.gnu.org/licenses/>.


   Description: Your typical run-of-the-mill TFTP (simple network time
     protocol client) ...

   Changes:

   2021-07-10: Create base on sntp.cpp

*/





#include <bios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"

#include "trace.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "udp.h"
#include "dns.h"
#include "timer.h"



#define SERVER_ADDR_NAME_LEN (80)



char     ServerAddrName[ SERVER_ADDR_NAME_LEN ];
char     FileName[ 128 ];
IpAddr_t ServerAddr;
uint16_t ServerPort = 69;

uint16_t SendEOF = 0;
uint16_t BlockNum = 1;
uint16_t TimeoutSecs = 3;
uint8_t  Verbose = 0;
uint8_t  SendFile = 0;

time_t   TargetTime = 0;

enum tftp_opcode_t {
  TFTP_RRQ = 1,
  TFTP_WRQ,
  TFTP_DATA,
  TFTP_ACK,
  TFTP_ERROR,
  TFTP_OACK,
};


// Ctrl-Break and Ctrl-C handler.  Check the flag once in a while to see if
// the user wants out.

volatile uint8_t CtrlBreakDetected = 0;

void __interrupt __far ctrlBreakHandler( ) {
  CtrlBreakDetected = 1;
}


typedef struct {

  UdpPacket_t udpHdr;   // Space for Ethernet, IP and UDP headers
  char buf[512+4];
} TFTP_packet_t;


TFTP_packet_t Outgoing;


// Function prototypes

void parseArgs( int argc, char *argv[] );
void shutdown( int rc );

int makeACK(char *buf, int blknum);
int makeRequest(char *buf, int opcode, char *filename, char *mode, int blksize,
  int timeout, int tsize);
int8_t sendRequest( int );
void putUdpHandler( const unsigned char *packet, const UdpHeader *udp );
void getUdpHandler( const unsigned char *packet, const UdpHeader *udp );
void send();
void recive();

char *strpcpy(char *dest, char *src, int *pos)
{
  while(*src)
  {
    *(dest + *pos) = *src++;
    (*pos)++;
  }
  *(dest + *pos) = '\0';
  (*pos)++;
  return dest-1;
}

FILE *targetFile;

char printTimeStampBuffer[40];

char * printTimeStamp( uint32_t ts, uint16_t local ) {

  time_t ts1 = ts;

  struct tm tmbuf;

  if ( local ) {
    _localtime( &ts1, &tmbuf );
  }
  else {
    _gmtime( &ts1, &tmbuf );
  }

  sprintf( printTimeStampBuffer, "%04d-%02d-%02d %02d:%02d:%02d",
          tmbuf.tm_year+1900, tmbuf.tm_mon+1, tmbuf.tm_mday,
          tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec );

  return printTimeStampBuffer;

}




int16_t setDosDateTime( void ) {

  struct dosdate_t dos_date;
  struct dostime_t dos_time;


  time_t ts1 = TargetTime;

  struct tm tmbuf;
  _localtime( &ts1, &tmbuf );

  dos_date.year = tmbuf.tm_year + 1900;
  dos_date.month = tmbuf.tm_mon+1;
  dos_date.day = tmbuf.tm_mday;

  int rc1 = _dos_setdate( &dos_date );

  dos_time.hour = tmbuf.tm_hour;
  dos_time.minute = tmbuf.tm_min;
  dos_time.second = tmbuf.tm_sec;
  dos_time.hsecond = 50;

  int rc2 = _dos_settime( &dos_time );

  if (rc1 || rc2 ) return 1;

  return 0;
}



static char CopyrightMsg1[] = "mTCP TFTP Client by Hiroki Mori (C)opyright 2021\n";
static char CopyrightMsg2[] = "Version: " __DATE__ "\n\n";


int main( int argc, char *argv[] ) {

  int mainRc = 1;

  printf( "%s  %s", CopyrightMsg1, CopyrightMsg2 );

  parseArgs( argc, argv );

  TimeoutSecs = TimeoutSecs * 1000;

  // Initialize TCP/IP
  if ( Utils::parseEnv( ) != 0 ) {
    exit( 1 );
  }


  // No sockets, no buffers TCP buffers
  if ( Utils::initStack( 0, 0, ctrlBreakHandler, ctrlBreakHandler ) ) {
    puts( "Failed to initialize TCP/IP - exiting" );
    exit( 1 );
  }


  // From this point forward you have to call the shutdown( ) routine to
  // exit because we have the timer interrupt hooked.


  printf( "Resolving %s, press [ESC] to abort.\n", ServerAddrName );

  // Resolve the name and definitely send the request
  int8_t rc = Dns::resolve( ServerAddrName, ServerAddr, 1 );
  if ( rc < 0 ) {
    puts( "Error resolving server" );
    shutdown( 1 );
  }


  uint8_t userEarlyExit = 0;

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  while ( 1 ) {

    if ( CtrlBreakDetected ) {
      puts( "Ctrl-Break detected: aborting\n" );
      userEarlyExit = 1;
      break;
    }

    if ( bioskey(1) != 0 ) {
      char c = bioskey(0);
      if ( (c == 27) || (c == 3) ) {
        puts( "Ctrl-C or ESC detected: aborting\n" );
        userEarlyExit = 1;
        break;
      }
    }

    if ( !Dns::isQueryPending( ) ) break;

    PACKET_PROCESS_SINGLE;
    Arp::driveArp( );
    Dns::drivePendingQuery( );

  }

  if ( userEarlyExit ) {
    shutdown( 1 );
  }


  // Query is no longer pending or we bailed out of the loop.
  rc = Dns::resolve( ServerAddrName, ServerAddr, 0 );

  if ( rc != 0 ) {
    puts( "Error resolving server name - exiting" );
    shutdown( 1 );
  }

  if (SendFile)
    send();
  else
    recive();

  shutdown( mainRc );

  // Never get here - we return from shutdown
  return 0;
}

void send()
{

  targetFile = fopen( FileName, "rb" );

  // Register UDP Handler - should never fail
  Udp::registerCallback( 1024, putUdpHandler );

  int len = makeRequest((char *)&Outgoing.buf, TFTP_WRQ, FileName, "octet", 512, 0, 0);

  int rc = sendRequest( len );

  if ( rc == -1 ) {
    puts( "Error: Unable to send UDP packets!" );
    exit( 1 );
  }
      
  // Spin again until we get a response

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  while ( TargetTime == 0 ) {

    if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( TimeoutSecs ) ) {
      TRACE_WARN(( "Sntp: Timeout waiting for tftp response\n" ));
      puts( "Timeout waiting for server response" );
      exit( 1 );
    }

    PACKET_PROCESS_SINGLE;
    Arp::driveArp( );

  }

  fclose( targetFile );
}


void recive()
{

  targetFile = fopen( FileName, "wb" );

  // Register UDP Handler - should never fail
  Udp::registerCallback( 1024, getUdpHandler );


  int len = makeRequest((char *)&Outgoing.buf, TFTP_RRQ, FileName, "octet", 512, 0, 0);

  int rc = sendRequest( len );

  if ( rc == -1 ) {
    puts( "Error: Unable to send UDP packets!" );
    exit( 1 );
  }
      
  // Spin again until we get a response

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  while ( TargetTime == 0 ) {

    if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( TimeoutSecs ) ) {
      TRACE_WARN(( "Sntp: Timeout waiting for tftp response\n" ));
      puts( "Timeout waiting for server response" );
      exit( 1 );
    }

    PACKET_PROCESS_SINGLE;
    Arp::driveArp( );

  }

  fclose( targetFile );
}
  




char *HelpText[] = {
  "\ntftp [options] <ipaddr>\n",
  "Options:",
  "  -help          Shows this help",
  "  -port <n>      Contact server on port <n> (default=123)",
  "  -retries <n>   Number of times to retry if no answer (default=1)",
  "  -set           Set the system time (default is not to)",
  "  -timeout <n>   Seconds to wait for a server response (default=3)",
  NULL
};





void usage( void ) {
  uint8_t i=0;
  while ( HelpText[i] != NULL ) {
    puts( HelpText[i] );
    i++;
  }
  exit( 1 );
}



void parseArgs( int argc, char *argv[] ) {

  int i=1;
  for ( ; i<argc; i++ ) {

    if ( argv[i][0] != '-' ) break;

    if ( stricmp( argv[i], "-help" ) == 0 ) {
      usage( );
    }
    else if ( stricmp( argv[i], "-port" ) == 0 ) {
      i++;
      if ( i == argc ) {
        usage( );
      }
      ServerPort = atoi( argv[i] );
      if ( ServerPort == 0 ) {
        puts( "Bad parameter for -port: can not use 0" );
        usage( );
      }
    }
    else if ( stricmp( argv[i], "-send" ) == 0 ) {
      SendFile = 1;
    }
    else if ( stricmp( argv[i], "-timeout" ) == 0 ) {
      i++;
      if ( i == argc ) {
        usage( );
      }
      TimeoutSecs = atoi( argv[i] );
      if ( TimeoutSecs == 0 ) {
        puts( "Bad parameter for -timeout: Should be greater than 0" );
        usage( );
      }
    }
    else if ( stricmp( argv[i], "-v" ) == 0 ) {
      Verbose = 1;
    }
    else {
      printf( "Unknown option %s\n", argv[i] );
      usage( );
    }

  }

  if ( i == argc ) {
    puts( "You need to specify a machine name or IP address" );
    usage( );
  }

  strncpy( ServerAddrName, argv[i], SERVER_ADDR_NAME_LEN );
  ServerAddrName[ SERVER_ADDR_NAME_LEN - 1 ] = 0;

  strcpy( FileName, argv[i+1] );

}



void shutdown( int rc ) {
  Utils::endStack( );
  exit( rc );
}

int makeACK(char *buf, int blknum)
{
  buf[0] = 0;
  buf[1] = TFTP_ACK;
  buf[2] = blknum >> 8;
  buf[3] = blknum & 0xff;
  return 4;
}

int makeRequest(char *buf, int opcode, char *filename, char *mode, int blksize,
  int timeout, int tsize)
{
  int pos = 0;
  char tmp[10];

  buf[pos++] = 0;
  buf[pos++] = opcode;

  strpcpy(buf, filename, &pos);
  strpcpy(buf, mode, &pos);

  if (blksize != 512) {
    sprintf(tmp, "%u", blksize);
    strpcpy(buf, "blksize", &pos);
    strpcpy(buf, tmp, &pos);
  }
  if (timeout) {
    sprintf(tmp, "%u", timeout);
    strpcpy(buf, "timeout", &pos);
    strpcpy(buf, tmp, &pos);
  }
  if (tsize) {
    sprintf(tmp, "%u", tsize);
    strpcpy(buf, "tsize", &pos);
    strpcpy(buf, tmp, &pos);
  }

  return pos;
}


int8_t sendRequest( int reqLen ) {

  // Setup outgoing packet

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  int rc = Udp::sendUdp( ServerAddr, 1024, ServerPort, reqLen,
                         (uint8_t *)&Outgoing, 1 );

  if ( rc == -1 ) return -1;

  // Spin and process packets until we can resolve ARP and send our request
  while ( rc == 1 ) {

    if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( 2000 ) ) {
      TRACE_WARN(( "Sntp: Arp timeout sending request\n" ));
      puts( "Warning: ARP timeout sending request - check your gateway setting" );
      return -1;
    }

    PACKET_PROCESS_SINGLE;
    Arp::driveArp( );

    rc = Udp::sendUdp( ServerAddr, 1024, ServerPort, reqLen,
                       (uint8_t *)&Outgoing, 1 );

    if ( rc == -1 ) return -1;

  }

  return 0;

}

void putUdpHandler( const unsigned char *packet, const UdpHeader *udp ) {

  int off = sizeof(UdpPacket_t);
  unsigned int pkttyp = packet[off+0] << 8 | packet[off+1];

  if (Verbose)
    printf("MORIMORI R %d\n", pkttyp);

  ServerPort = ntohs(udp->src);

  if (pkttyp == TFTP_ACK) {
    if (SendEOF == 0) {
    
      Outgoing.buf[0] = 0x00;
      Outgoing.buf[1] = TFTP_DATA;
      Outgoing.buf[2] = BlockNum >> 8;
      Outgoing.buf[3] = BlockNum & 0xff;
      ++BlockNum;
      if (BlockNum == 0)
        BlockNum = 1;
      int len = fread( &Outgoing.buf[4], 1, 512, targetFile );
      sendRequest(len + 4);
      if (len != 512)
        SendEOF = 1;
    } else {
      // Last ack
      TargetTime = 1;
    }
  } else {
    TargetTime = 1;
  }

  Buffer_free( packet );
}

void getUdpHandler( const unsigned char *packet, const UdpHeader *udp ) {

  int off = sizeof(UdpPacket_t);
  unsigned int pkttyp = packet[off+0] << 8 | packet[off+1];
  unsigned int blknum = packet[off+2] << 8 | packet[off+3];
  int size = ntohs(udp->len) - 8;
  if (Verbose)
    printf("MORIMORI recv %d %x %d %d\n", (unsigned short)ntohs(udp->src), pkttyp, blknum, ntohs(udp->len) - 8);

  ServerPort = ntohs(udp->src);

  if (pkttyp == TFTP_DATA) {

    int len = makeACK((char *)&Outgoing.buf, blknum);
    sendRequest(len);

  // Quick sanity check

    if ( size > 4 ) {
      int rc = fwrite( packet + off + 4, size - 4, 1, targetFile );
    }

    if (size != 512 + 4)
      TargetTime = 1;
  }
  if (pkttyp == TFTP_ERROR) {
      TargetTime = 1;
  }

  // We are done processing this packet.  Remove it from the front of
  // the queue and put it back on the free list.
  Buffer_free( packet );

}

