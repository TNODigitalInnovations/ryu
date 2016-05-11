#include <stdint.h>
#include "ofsoft-bpf.h"
#define ETH_HLEN 14
#define UDP_HLEN 8

static inline int tlv_len_offset(uint8_t *buff, int currpos, uint64_t *TLVlen, uint8_t *TLVlenK){
	uint8_t len0 = buff[currpos++]; //get length and advance
	uint64_t len = 0;
	uint8_t lenK = 1;

	if (len0<253)
		len=len0;
	else {
		//length encoded in following 2,4,or 8 octets
		switch (len0){
		case 253 :
			lenK=2;
			break;
		case 254 :
			lenK=4;
			break;
		case 255 :
			lenK=8;
			break;
		default :
			//printf("wrong ndn datagram format!\n");
			return(0);

		}
		uint8_t i;
		for(i=0; i<lenK; i++){
			len = len * 256 + buff[currpos++];
		}
		lenK++; //account for the fact that first octet plays now indication role
	}
	*TLVlen = len;
	*TLVlenK = lenK;
	return(-1);
}

static inline int pattern_found_fun(uint8_t *buff,uint8_t *pattern, int currpos, uint64_t TLVlen){
	uint64_t i;
	for (i=0;i<TLVlen;i++){
		if(buff[currpos+i]!=pattern[i]){
			return(0);
	    }
	}
	return(1);
}


uint64_t icn_filter(void *ptr){ //load it with -m

	struct ofsoft_bpf * bpfparams = (struct ofsoft_bpf *) ptr;

	uint8_t *buff = bpfparams->packet;
	uint8_t *pattern = bpfparams->param;

	int currpos = 0;
	uint16_t eth_type;
	uint16_t udp_srcport;
	uint32_t ip_hlen;
	uint8_t ndn_type;


	currpos = 12;

	eth_type = (uint16_t)buff[currpos]*256 + (uint16_t)buff[(currpos+1)];

	if (eth_type != 0x0800){
//		printf("wrong eth_type 0x%04x\n",eth_type);
		return(0);
	}

	if (buff[23] != 0x11){
//		printf("not UDP!\n");
		return(0);
	}

	ip_hlen = 4 * (buff[14] & 0xF);
//	printf("ip header length = %d\n",ip_hlen);

	currpos = ETH_HLEN + ip_hlen; //go to UDP source port
	udp_srcport = (uint16_t)buff[currpos]*256 + (uint16_t)buff[(currpos+1)];
	if (udp_srcport != 0xdc2b){  //not 56363 ?
//		printf("not 56363 UDP port!\n");
		return(0);
	}

	currpos+=UDP_HLEN; //move to the payload of UDP, i.e., NDN packet

	ndn_type = buff[currpos];
	if (ndn_type != 0x05){  //not an interest ?
//		printf("not interest ndn datagram!\n");
		//TODO
		return(0);
	}


	uint64_t TLVlen,totallen;
	uint8_t TLVlenK;

	currpos+=1; //first octet of length
	//TODO call with assert 1?
	tlv_len_offset(buff, currpos, &totallen, &TLVlenK);
	currpos+=TLVlenK;


//	printf("total ndn field length = %llu\n",totallen);
	totallen += ETH_HLEN + ip_hlen + UDP_HLEN;

//	printf("currpos= %d\n",currpos);

	if (buff[currpos] != 0x07){  //not an name ?
//		printf("not name field!\n");
		return(0);
	}

	currpos++;
	tlv_len_offset(buff, currpos, &TLVlen, &TLVlenK);
	currpos+=TLVlenK;
//	printf("currpos= %d\n",currpos);

	int pattern_found=1;

	while (currpos<totallen){

		if (buff[currpos] != 0x08){  //not an name ?
//			printf("not name component field!\n");
			return(0);
		}

		currpos++;
		tlv_len_offset(buff, currpos, &TLVlen, &TLVlenK);
		currpos+=TLVlenK; //move to content

		pattern_found=pattern_found_fun(buff,pattern,currpos,TLVlen);
		/* for whatever reason (too many nested loops/ifs?)
		 * this will not work: as soon as we try to do something with
		 * variable pattern_found the program will crash
		//return(pattern_found);
		for (i=0;i<TLVlen;i++){
			if(buff[currpos+i]!=pattern[i]){
				pattern_found=0;
			}

		}
		*/

		if (pattern_found>0){
			return(-1);
		}

		currpos+=TLVlen;

	}
	return(0);
}


