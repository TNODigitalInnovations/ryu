#include <stdint.h>
#include "ofsoft-bpf.h"

uint64_t deadbeef(void * ptr)
{
	struct ofsoft_bpf * bpfparams = (struct ofsoft_bpf *) ptr;
/*
	bpfparams->table_id;
	bpfparams->in_port;

	bpfparams->param_len;
	bpfparams->param;

	bpfparams->packet_len;
	bpfparams->packet;
*/
	if (bpfparams->packet_len > 20)
	{
		uint64_t * res = (uint64_t *) (bpfparams->packet + 12);
		return *res;
	}

	return 0xDEADBEEF;
}
