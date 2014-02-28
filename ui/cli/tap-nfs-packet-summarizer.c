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

#define ETH_HEADER_LEN 14u
#define IP_HEADER_LEN 20u
#define TCP_HEADER_LEN_OFFSET ETH_HEADER_LEN+IP_HEADER_LEN+12

#define RPC_SEG_LEN_OFFSET 0x42
#define NFS_PACKET_REPLY_START 0x24
#define NFS_PACKET_CALL_START 0x70
#define FIRST_OPLEN_OFFSET 0x08
#define WRITE_LEN_OFFSET 0x20
#define READ_LEN_OFFSET 0x0c
#define WRITE_LEN_MOD 0x04
#define READ_LEN_MOD 0x04
#define WRITE_OP 0x26
#define READ_OP 0x19
#define MESSAGE_TYPE_OFFSET 0x08
#define CALL 0x00
#define REPLY 0x01
#define MAX_PACKET_LEN 1500u
#define ERR -1
#define OP_NOT_HANDLED 0
#define DEBUG 1

/* Fixed lengths of various standard NFS operations */
#define ACCESS 0x03
#define ACCESS_LEN 4
#define SEQUENCE 0x35
#define SEQUENCE_LEN 8
#define REPLY_SEQUENCE_LEN 10
#define PUTFH 0x16

#define VALIDATE_PACKET_OFFSET(packet_offset, max_len)                         \
            /*                                                                 \
             * If this validation fails, there is something terribly wrong!    \
             * Some defensive code to ensure that program doesn't crash.       \
             */                                                                \
           if(packet_offset > max_len) {        \
                printf("ERR:Packet offset going out of bounds, skipping packet");\
                return ERR;                          \
            }

#define TCP_IP_HEADER_LEN(header_start) \
        /* Take higher order 4 bits for header length */ \
        ETH_HEADER_LEN + IP_HEADER_LEN + ((*(header_start + TCP_HEADER_LEN_OFFSET))>>2)

char* print_columns_ci(column_info *ci);
wtap_dumper *pdumper;
packet_info *saved_pinfo;
guint8 *saved_packet_header;


/* Temporary object to hold state for the tap */
typedef struct nfs_packet_summarizer_state{
    gint32 i;
} nfs_packet_summarizer_state_t;

nfs_packet_summarizer_state_t *nfs_state;

/* Stream used to output the packet information */
/* TODO: What about multiple threads, if we happen to use multithreading? */
print_stream_t* print_stream;

void
write_word(guint8* data, int offset, int value, guint8 base){
    offset += base;
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
read_word(guint8 *data, gint32 offset){
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
summarize_read_packets(guint8 *data, tvbuff_t *tvb, guint32 packet_offset, 
                       guint8 tcp_header_len){
    guint32 read_word_len =0;
    guint8 *tvb_data = (guint8*) tvb->real_data;
    /*
     * Move to the position where read reply data are present
     */
    packet_offset += READ_LEN_OFFSET;
    /*
     * Get read length for this NFS packet and update new read
     * length to READ_LEN_MOD
     */
    VALIDATE_PACKET_OFFSET(packet_offset, tvb->length);
    read_word_len = read_word(tvb_data, packet_offset);
    write_word( data, packet_offset, READ_LEN_MOD, tcp_header_len);
    packet_offset += 4;
    /*
     * Put the length of the read as data for read operation
     */
    write_word( data, packet_offset, read_word_len, tcp_header_len);
    //TODO: Will there be a 3rd operation?
    return packet_offset + tcp_header_len + 4;
}

int
summarize_write_packets(guint8 *data, tvbuff_t *tvb, guint32 packet_offset,
                        guint8 tcp_header_len){
        int op_data_len;
        guint32 third_op_start;
        guint nfs_op;
        guint8 *tvb_data = (guint8*) tvb->real_data;
        packet_offset += WRITE_LEN_OFFSET;
        /*
         * Read length of the write operation
         */
        VALIDATE_PACKET_OFFSET(packet_offset, tvb->length);
        op_data_len = read_word(tvb_data, packet_offset);
        #ifdef DEBUG
        printf("Length of write:%d\n",op_data_len);
        fflush(NULL);
        #endif
        /*
         * Overwrite length of write operation with 4
         */
        write_word(data, packet_offset, WRITE_LEN_MOD, tcp_header_len);
        packet_offset += 4;
        /*
         * Overwrite content of write operation with length of write
         */
        write_word(data, packet_offset, op_data_len, tcp_header_len);
        third_op_start = packet_offset + op_data_len;
        packet_offset += WRITE_LEN_MOD;
        /*
         * Align at 4 byte boundary if not aligned
         */
        if((third_op_start & 0x3) != 0){
            third_op_start = (third_op_start & 0xfffffffc) + 4;
        }
        VALIDATE_PACKET_OFFSET(packet_offset, tvb->length);
        nfs_op = read_word(tvb_data, third_op_start);
        #ifdef DEBUG
        printf("Operation after write:%d\n",nfs_op);
        #endif
        /*
         * Copy contents of the third operation into the new buffer
         */
        memcpy(data + tcp_header_len + packet_offset,
                tvb_data + third_op_start,
                tvb->length - third_op_start);
        return tcp_header_len + packet_offset + tvb->length - third_op_start;
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

void 
printnbytes(const guint8 *data, int n){
    int i;
    for(i = 0; i < n; i++){
        if( i%20 == 0 ) printf ("\n");
        printf("%x ", *(data+i));
    }
}


/*
 * Get length of the NFS operation. Only few cases that are relevent are 
 * addressed here. TODO: Observe this part with enhancements.
 */
gint32
get_op_data_len(gint8 message_type, gint32 nfs_op, guint32 packet_offset, guint8 *tvb_data){
    if(message_type == REPLY){
        switch(nfs_op){
            case ACCESS: return ACCESS_LEN * 4; 
            case SEQUENCE:  return REPLY_SEQUENCE_LEN * 4;
            default: return 1 * 4; //NFS_OK
        }
    } else if(message_type == CALL){
        switch(nfs_op){
            case SEQUENCE: return SEQUENCE_LEN * 4;
            case PUTFH:
                //packet_offset points to the operation itself
                return (4 + read_word(tvb_data, packet_offset)); 
            default: return 2 * 4;
        }
    } else {
        /* Won't reach here */
        return -1;
    }
}

guint32
resolve_rpc_header_len(guint8 *tvb_data, gint8 message_type){

/* 
 * RPC header + NFS header structure for message type == CALL:
|...RPC...|Cred_len....|..Ver_len..|tag_len..|min_ver|opertion.. | operation.. |....

 * RPC header + NFS header structure for message type == REPLY:
|...RPC...|..Ver_len..|Accept_state | NFS_reply_satus | tag_len..|opertion.. | operation.. |....
 */
    int offset;
    guint32 len;
    if(message_type == CALL){
    // |Frag_header | XID | Message_type | RPC version | Pgm | pgmversion | Procedure
        offset = 0x1c; 
        //TODO: MACRO for this
        offset += 4; //credential type
        len = read_word(tvb_data, offset);
        offset += 4 + len;//rpc credential len
        //Verifier
        offset += 4;//AUTH Method word
        //verifier len
        len = read_word(tvb_data, offset);
        offset += 4 + len;
        //Read tag length
        len = read_word(tvb_data, offset);
        offset += 4 + len;
        offset += 4;//minor version increment
    } else{
    // |Frag_header | XID | Msg_type | Reply_state |
        offset = 0x10;
        //Verifier
        offset += 4;//AUTH Method word
        //verifier len
        len = read_word(tvb_data, offset);
        offset += 4 + len;
        //| Accespt_state | NFS_reply_status |
        offset += 8;
        //Read tag length
        len = read_word(tvb_data, offset);
        offset += 4 + len;
    }
    return offset;
}

int
is_read_write (tvbuff_t *tvb, guint32 *packet_offset_ptr){
        guint32 packet_offset;
        gint32 nfs_op;
        gint32 op_data_len;
        gint8 message_type;
        guint8 *tvb_data;
        guint32 num_ops;
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
        if(message_type == CALL || message_type == REPLY){
            packet_offset = resolve_rpc_header_len(tvb_data, message_type);
            packet_offset += 4; // Message type itself
        } else {
            /*
             * We don't know what message type it is, we don't handle this. Return.
             */
            return -1;
        }
        VALIDATE_PACKET_OFFSET(packet_offset-4, tvb->length);
        num_ops = read_word(tvb_data, packet_offset-4);
        #ifdef DEBUG
        printf("Number of operations: %d\n",num_ops);
        #endif
    /* Read number of NFS operations in one COMPOUND operation */
     while(num_ops > 0){
        num_ops --;
        /*
         * Read first operation this NFS packet embeds
         */
        VALIDATE_PACKET_OFFSET(packet_offset, tvb->length);
        nfs_op = read_word(tvb_data, packet_offset);
        #ifdef DEBUG
        printf("Nfs operation is : %x ",nfs_op);
        #endif

        /*
         * Determine what operation this packet contains
         */
        if(nfs_op == READ_OP && message_type == REPLY ){
            *packet_offset_ptr = packet_offset;
            return nfs_op;
        } else if(nfs_op == WRITE_OP && message_type == CALL) {
            *packet_offset_ptr = packet_offset;
            return nfs_op;
        } 
        /*
         * Read length of the data for this operation
         */
        packet_offset += 4;
        op_data_len = get_op_data_len(message_type, nfs_op, packet_offset, tvb_data);
        packet_offset += op_data_len;
     }
     /*
      * We don't handle any other operation for MSP, skip processing this
      * NFS packet
      */
      return ERR;
}

/*
 * Returns offset within the new packet at which the data section ends
 */
int
operate_nfs_data(guint8* data, tvbuff_t *tvb){
    guint32 packet_offset;
    gint32 nfs_op = is_read_write(tvb, &packet_offset);
    guint8 tcp_header_len = TCP_IP_HEADER_LEN(data);
    if( nfs_op == WRITE_OP){
        #ifdef DEBUG
            printf("\nWrite packet..");
        #endif
        return summarize_write_packets( data, tvb, packet_offset, tcp_header_len);
    } else if (nfs_op == READ_OP){
        #ifdef DEBUG
            printf("\nRead packet..");
        #endif
        return summarize_read_packets( data, tvb, packet_offset, tcp_header_len);
    } else {
        /*
         * Ideally control should not reach here.
         */
        return ERR;
    }
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
set_rpc_seglen(guint8 *new_data, gint32 seglen)
{
    /*
     * Every packet that has reached this point has packet size > 1444
     */
    *(new_data + RPC_SEG_LEN_OFFSET + 1) = (guint8)((seglen & 0xff0000)>>16);
    *(new_data + RPC_SEG_LEN_OFFSET + 2) = (guint8)((seglen & 0x00ff00)>>8); 
    *(new_data + RPC_SEG_LEN_OFFSET + 3) = (guint8)((seglen & 0x0000ff));
}
/*
 * Create a new compressed NFS packet from the original NFS packet(s).
 */
gboolean
handle_nfs_read_write(packet_info *pinfo, epan_dissect_t *edt, tvbuff_t *tvb){
    gint32 caplen = 0;
    gint32 err = 0;
    guint8 *new_data = NULL;
    guint32 max_new_data_packet_len;
    guint8 tcp_header_len;
    new_data = (guint8*)g_malloc( MAX_PACKET_LEN );
    if(saved_packet_header != NULL) {
        /*
        * This is an NFS Multi Segment Packet (MSP). Copy TCP header
        * from the first TCP packet of this MSP stream.
        */
        #ifdef DEBUG
        printnbytes(saved_packet_header, 80);
        #endif
        tcp_header_len = TCP_IP_HEADER_LEN(saved_packet_header);
        memcpy(new_data, saved_packet_header, tcp_header_len);
    } else {
        /*
         * This is not an MSP, copy packet header of the same packet.
         */
         tcp_header_len = TCP_IP_HEADER_LEN((edt->tvb->real_data));
         memcpy(new_data, edt->tvb->real_data, tcp_header_len);
    }
    max_new_data_packet_len = (MAX_PACKET_LEN > tvb->length + tcp_header_len
                                ? tvb->length
                                : MAX_PACKET_LEN - tcp_header_len);
    memcpy(new_data + tcp_header_len,
            tvb->real_data,
            max_new_data_packet_len);
    /*
     * Create the NFS packet and reinitialize capture length of this new
     * packet .Cap length limiting ensures that only required length of
     * packet data is written onto the cap file
     */
    caplen = operate_nfs_data(new_data, tvb);
    if(caplen == ERR) {
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
    /* Set length of the RPC segment for this NFS packet */
    set_rpc_seglen(new_data, caplen - tcp_header_len - 4);
    wtap_dump(pdumper, pinfo->phdr, new_data, &err);
    cleanup_tap_step(new_data);
    return TRUE;
}

gboolean
nfs_packet_summarizer_packet(void *tapdata,
            packet_info *pinfo,
            epan_dissect_t *edt,
            const void *data){
    gint32 err = 0;
    tvbuff_t *tvb = (tvbuff_t*)data;
    guint32 packet_offset;
    gboolean ret;
    if(pdumper == NULL){
        printf("Could not open file dumper for NFS packet summarizer\n");
        return FALSE;
    }
    if(data != NULL){
        /*
         * This is an NFS packet, decide whether it needs zipping or not.
         */
         if(is_read_write(tvb, &packet_offset) > 0){
            /*
             * This is an NFS packet that has read/write operations within its
             * compound procedure. A new aggregate NFS packet has to be created
             * for this packet.
             */
            ret = handle_nfs_read_write(pinfo, edt, tvb);
            if(!ret){
                return FALSE;
            }
         } else {
            /*
             * It is not a read/write packet, no modification is required for the
             * packet. Output the packet as it is.
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
            saved_packet_header = (guint8*)g_malloc(TCP_IP_HEADER_LEN(edt->tvb->real_data));
            memcpy(saved_packet_header, edt->tvb->real_data, TCP_IP_HEADER_LEN(edt->tvb->real_data));
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
nfs_packet_summarizer_draw(void *tapdata){
    /*
     * I don't see any immediate implications of writing packets out asynchronously
     * But possibly this is an optimization in mind
     */
    if(0) printf("%p", tapdata);
}

void
nfs_packet_summarizer_reset(void *tapdata){
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
    gint link_type          = WTAP_ENCAP_ETHERNET;
    gint32 snapshot_length  = 1000; //TODO: Does it realy matter?
    gboolean compressed     = FALSE;
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
register_tap_listener_nfs_packet_summarizer(void){
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
    nfs_state = g_new(nfs_packet_summarizer_state_t,1);
    #ifdef DEBUG
    printf("Registering NFS packet summarizer listener\n");
    #endif
    register_tap_listener("nfs_packet_summarizer", (void*)nfs_state, NULL, 0,
                nfs_packet_summarizer_reset,
                nfs_packet_summarizer_packet,
                nfs_packet_summarizer_draw);
}

void 
remove_tap_listener_nfs_packet_summarizer(void){
    remove_tap_listener((void*) nfs_state);
}
