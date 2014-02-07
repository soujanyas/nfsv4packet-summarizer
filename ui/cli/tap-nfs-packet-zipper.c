#include "config.h"
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <stdio.h>
#include <epan/column-info.h>
#include <epan/print.h>
#include <wiretap/wtap.h>
#include <epan/epan_dissect.h>
#include <epan/tvbuff-int.h>
#include <unistd.h>
#define TCP_HEADER_LEN 0x42
#define TCP_SEGLEN_OFFSET 0x42
#define NFS_PACKET_READ_START 0x24
#define NFS_PACKET_WRITE_START 0x70
#define FIRST_OPLEN_OFFSET 0x08
#define WRITE_LEN_OFFSET 0x20
#define READ_LEN_OFFSET 0x0c
#define WRITE_LEN_MOD 0x04
#define READ_LEN_MOD 0x04
#define WRITE_OP 0x26
#define READ_OP 0x19
#define MESSAGE_TYPE_OFFSET 0x08
#define MESSAGE_TYPE_CALL 0x00
#define MESSAGE_TYPE_REPLY 0x01
#define MAX_PACKET_LEN 1500
#define DEBUG 1

#define VALIDATE_PACKET_OFFSET(packet_offset, tvb)  \
           if(packet_offset > tvb->length) {        \
                printf("ERR:Packet offset going out of bounds, skipping packet");\
                return -1;                          \
            }    

char* print_columns_ci(column_info *ci);
wtap_dumper *pdumper;
packet_info *saved_pinfo;
guint8 *saved_packet_header;


/* Temporary object to hold state for the tap */
typedef struct nfs_packet_zipper_state{
	gint32 i;
} nfs_packet_zipper_state_t;

nfs_packet_zipper_state_t *nfs_state;

/* Stream used to output the packet information */
/* TODO: What about multiple threads, if we happen to use multithreading? */
print_stream_t* print_stream;

void
write_word(guint8* data, int offset, int value){
	offset += TCP_HEADER_LEN;
    *(data + offset + 0) = (guint8)((value & 0xff000000) >> 24);
    *(data + offset + 1) = (guint8)((value & 0x00ff0000) >> 16);
    *(data + offset + 2) = (guint8)((value & 0x0000ff00) >> 8);
    *(data + offset + 3) = (guint8)((value & 0x000000ff));
}

/* 
 * Reads 4 bytes of data that is in big endian format into
 * a variable 
 */
int 
read_word(guint8 *data, int offset){
	guint8 b4,b3,b2,b1;
	int content;
	b4 = *(data + offset);
	b3 = *(data + offset + 1);
	b2 = *(data + offset + 2);
	b1 = *(data + offset + 3);
	content = (b4 << 24) + (b3 << 16) + (b2 << 8) + (b1);
	return content;
}

int
zip_read_packets(guint8 *data, guint8 *tvb_data, guint32 packet_offset){
	guint32 read_word_len =0;
	/* 
	 * Move to the position where read reply data are present 
	 */
	packet_offset += READ_LEN_OFFSET;
	/* 
	 * Get read length for this NFS packet and update new read 
	 * length to READ_LEN_MOD 
	 */
	read_word_len = read_word(tvb_data, packet_offset);
	write_word( data, packet_offset, READ_LEN_MOD);
	packet_offset += 4;
	/* 
	 * Put the length of the read as data for read operation 
	 */
	write_word( data, packet_offset, read_word_len);
	//TODO: Will there be a 3rd operation?
	return packet_offset + TCP_HEADER_LEN + 4;
}	

int
zip_write_packets(guint8 *data, tvbuff_t *tvb, int packet_offset){
		int op_data_len;
		guint32 third_op_start;
		guint nfs_op;
		guint8 *tvb_data = (guint8*) tvb->real_data;
		packet_offset += WRITE_LEN_OFFSET;
		/* 
		 * Read length of the write operation 
		 */
		op_data_len = read_word(tvb_data, packet_offset);
		/* 
		 * Overwrite length of write operation with 4 
		 */
		write_word(data, packet_offset, WRITE_LEN_MOD);
		packet_offset += 4;
		/* 
		 * Overwrite content of write operation with length of write 
		 */
		write_word(data, packet_offset, op_data_len);
		third_op_start = packet_offset + op_data_len;
        /*
         * If this validation fails, there is something terribly wrong! 
         * Some defensive code to ensure that program doesn't crash.
         */
        VALIDATE_PACKET_OFFSET(third_op_start, tvb);

		packet_offset += WRITE_LEN_MOD;
		/* 
		 * Align at 4 byte boundary if not aligned 
		 */
		if((third_op_start & 0x3) != 0){
			third_op_start = (third_op_start & 0xfffffffc) + 4;
		}
		nfs_op = read_word(tvb_data, third_op_start);
        printf("Operation : %x", nfs_op);
		/* 
		 * Copy contents of the third operation into the new buffer 
		 */
		memcpy(data + TCP_HEADER_LEN + packet_offset, 
				tvb_data + third_op_start, 
				tvb->length - third_op_start);
		return TCP_HEADER_LEN + packet_offset + tvb->length - third_op_start;
}

void
print_tvb_contents(tvbuff_t *tvb){
	unsigned int i ;
    #ifdef DEBUG
	printf("Printing tvb contents of length : %d\n",tvb->length);
    #endif
 	for(i = 0 ;i < tvb->length; i++){
		if(i%0x10 == 0){
			printf("\n%x ", i);
		}
		printf("%x ",*((tvb->real_data) + i));
	}
}
/* 
 * Returns offset within the new packet at which the data section ends 
*/
int 
operate_nfs_data(guint8* data, tvbuff_t *tvb){
		guint32 packet_offset = NFS_PACKET_READ_START;
		gint32 nfs_op;
		gint32 op_data_len;
		gint8 message_type;
        guint8 *tvb_data;
        #ifdef TRACE
        print_tvb_contents(tvb);
        #endif
		tvb_data = (guint8 *)tvb->real_data;
		/*
		 * Message type could be CALL or REPLY. Write embeds TCP stream in
		 * CALL and READ embeds TCP stream in REPLY. We needs to read NFS 
		 * operation information at different offsets in these cases.
		 */
		message_type = read_word(tvb_data, MESSAGE_TYPE_OFFSET);
		#ifdef DEBUG
		printf("Message type is:%d\n", message_type);
		#endif
		if(message_type == MESSAGE_TYPE_CALL){
			packet_offset = NFS_PACKET_WRITE_START;
		} else if(message_type == MESSAGE_TYPE_REPLY) {
			packet_offset = NFS_PACKET_READ_START;
		} else {
		/* 
			 * We don't know what message type it is, we don't handle this. Return.
			 */
			return -1;
		}
		packet_offset += 4;
		/* 
		 * Read first operation this NFS packet embeds 
		 */
		nfs_op = read_word(tvb_data, packet_offset);
		#ifdef DEBUG
		printf("Nfs operation is : %x ",nfs_op);
		#endif
		packet_offset += 4;
		/* 
		 * Read length of the data for this operation 
		 */
		op_data_len = read_word(tvb_data, packet_offset);
		packet_offset += (op_data_len + 4);	
        /*
         * If this validation fails, there is something terribly wrong! 
         * Some defensive code to ensure that program doesn't crash.
         */
        VALIDATE_PACKET_OFFSET(packet_offset, tvb);
		/* 
		 * Handle huge chunk of READ/WRITE data now
		 */
		nfs_op = read_word(tvb_data, packet_offset);
		#ifdef DEBUG
		printf("Nfs operation is : %x ",nfs_op);
        fflush(NULL);
		#endif
	    if( nfs_op == WRITE_OP){
			return zip_write_packets( data, tvb, packet_offset);
		} else if (nfs_op == READ_OP){
			return zip_read_packets( data, tvb_data, packet_offset);
		} else {
		/* 
			 * We don't handle any other operation for MSP, skip processing this 
		 	 * NFS packet
		 	 */
			return -1;
		}
        return -1;
}

/* 
 * Cleanup data, free gmalloced objects 
 */
void
cleanup_tap_step( guint8 *new_data){
	g_free(saved_packet_header);
	saved_packet_header = NULL;
   	g_free(new_data);
}

/*
 * Write summary of NFS packets in text format
 */
gboolean
print_packet_summary(packet_info *pinfo){
	char *line_buf;
	if( print_stream == NULL || pinfo == NULL )
		return FALSE;
	line_buf = print_columns_ci((column_info*)pinfo->cinfo);
	/* print_line_text */
	return print_stream->ops->print_line(print_stream, 0, line_buf);

}

/*
 * Set TCP segment length for this packet
 */
void
set_tcp_seglen(guint8 *new_data, gint32 seglen)
{
	/*guint8 b3,b2,b1;
	guint32 len;
	b3 = *(new_data+0x43);
	b2 = *(new_data+0x44);
	b1 = *(new_data+0x45);
	len = ((b3<<16) + (b2 <<8) +b1);*/
	/* 
	 * Every packet that has reached this point has packet size > 1444 
	 */
   	*(new_data + TCP_SEGLEN_OFFSET + 1) = (guint8)((seglen & 0xff0000)>>16);
    *(new_data + TCP_SEGLEN_OFFSET + 2) = (guint8)((seglen & 0x00ff00)>>8); 
   	*(new_data + TCP_SEGLEN_OFFSET + 3) = (guint8)((seglen & 0x0000ff));
}

gboolean 
nfs_packet_zipper_packet(void *tapdata, 
			packet_info *pinfo, 
			epan_dissect_t *edt,
			const void *data){
	gint32 err = 0;
	gint32 caplen = 0;
	guint8 *new_data = NULL;
	tvbuff_t *tvb = (tvbuff_t*)data;
    guint32 max_new_data_packet_len;
	if(pdumper == NULL){
		printf("Could not open file dumper for NFS packet zipper\n");
		return FALSE;
	}
	if(data != NULL){
		/* 
		 * This is an NFS packet, decide whether it needs zipping or not.
         *
         * TVB len check is required to ensure that interleaved packets 
         * don't harm our zipping operation.
         */
		if(saved_packet_header != NULL && tvb->length > MAX_PACKET_LEN) {
			/* 
			 * This is a part of the Multi Segment Packet. A new aggregate NFS 
			 * packet has to be created for this MSP. 
			 */
            max_new_data_packet_len = (MAX_PACKET_LEN > tvb->length + TCP_HEADER_LEN
                                             ? tvb->length 
                                             : MAX_PACKET_LEN - TCP_HEADER_LEN);
            new_data = (guint8*)g_malloc( MAX_PACKET_LEN );
			memcpy(new_data, saved_packet_header, TCP_HEADER_LEN);
			memcpy(new_data + TCP_HEADER_LEN, 
					tvb->real_data, 
					max_new_data_packet_len);
			/* 
			 * Create the NFS packet and reinitialize capture length of this new
			 * packet .Cap length limiting ensures that only required length of
			 * packet data is written onto the cap file
			 */
			caplen = operate_nfs_data(new_data, tvb);
			if(caplen == -1) {
				/* 
			 	 * There was an error zipping the packet, skip this packet 
			 	 */
				cleanup_tap_step(new_data);
				return FALSE;
			}
			#ifdef DEBUG
			printf("Capture len is : %x\n", caplen);
			#endif
			pinfo->phdr->caplen = caplen;
			set_tcp_seglen(new_data, caplen - TCP_HEADER_LEN);
		 	wtap_dump(pdumper, pinfo->phdr, new_data, &err);
			cleanup_tap_step(new_data);
		} else {
			/* 
			 * It is not a part of a Multi Segment packet, no modification is
			 * required for the packet. Output the packet as it is. 
			 */
			wtap_dump(pdumper, pinfo->phdr, edt->tvb->real_data, &err);
		}
		/* 
		 * In either case, write summary of packet onto a text file
		 */
		print_packet_summary(pinfo);
	} else {
	 	/* 
		 * Data was enqued to this tap from TCP dissector. Extract the header of
		 * the TCP packet and save it if it not saved already.
		 */
		if(saved_packet_header == NULL){
			/* Save the header from the packet enqueued by TCP */
			#ifdef DEBUG
			printf("NULL data - saving packet header\n");
			#endif
			saved_packet_header = (guint8*)g_malloc(TCP_HEADER_LEN);
			memcpy(saved_packet_header, edt->tvb->real_data, TCP_HEADER_LEN); 
		}
	}
	/* 
	 * To avoid compilation errors of unused variables 
	 */
	if(0){
		printf("%p %p %p %p",tapdata,pinfo,edt,data);
	}
	return TRUE;
}

void 
nfs_packet_zipper_draw(void *tapdata){
	/* 
	 * I don't see any immediate implications of writing packets out asynchronously
	 * But possibly this is an optimization in mind
	 */
	if(0) printf("%p", tapdata);	
}

void 
nfs_packet_zipper_reset(void *tapdata){
	gint32 err = 0;
	wtap_dump_close(pdumper, &err);//TODO: Does this 'error' signify something here?
	/*
	 * Close print destination
	 */
	print_stream->ops->destroy(print_stream);
	if(0) printf("%p", tapdata);
}


gboolean init_print_stream(void) {
	char* save_file_txt = (char*) "./tapped_data.txt";
	print_stream = print_stream_text_new(TRUE, save_file_txt);
	if(print_stream == NULL){
		return FALSE;
	}
	return TRUE;
}

gboolean init_pcap_stream(void) {
	char* save_file_pcap = (char*) "./tapped_data.pcap";
	gint32 outfile_type  = WTAP_FILE_TYPE_SUBTYPE_PCAP;
	//TODO: Can we get it from a valid source for this packet, so far it dint matter
	gint link_type 		 	= WTAP_ENCAP_ETHERNET; 
	gint32 snapshot_length  = 1000; //TODO: Does it realy matter?
	gboolean compressed  	= FALSE;
	gint32 err = 0;
	
	pdumper = wtap_dump_open (save_file_pcap, outfile_type, link_type,
							 snapshot_length, compressed, &err );
	if(pdumper == NULL){
		printf("Could not open dump file, not registering nfs_compressor listener\n");
		return FALSE;
	}
	return TRUE;
}

void 
register_tap_listener_nfs_packet_zipper(void){
	gboolean stream_init;
	/* 
	 * Create a stream object used to output the NFS operations in text format
	 */
	stream_init = init_print_stream();
	if(!stream_init){
		/* 
		 * Opening stream failed, no point doing any intialization 
		 */
		return;
	}
	/* 
	 * Create dumper used to output the NFS operations in pcap format
	 */
	stream_init = init_pcap_stream();
	if(!stream_init){
		/* 
		 * Opening stream failed, no point doing any intialization 
		 */
		return;
	}
	nfs_state = g_new(nfs_packet_zipper_state_t,1);
	#ifdef DEBUG
	printf("Registering NFS packet zipper listener\n");
	#endif
	register_tap_listener("nfs_packet_zipper", (void*)nfs_state, NULL, 0, 
				nfs_packet_zipper_reset,
				nfs_packet_zipper_packet,
				nfs_packet_zipper_draw);
}

void 
remove_tap_listener_nfs_packet_zipper(void){
	remove_tap_listener((void*) nfs_state);
}
