struct ofp_header {
    unsigned char version;
    unsigned char type;
    unsigned short length;
    unsigned long xid;
};

struct ofp_phy_port {
    unsigned short port_no;
    unsigned char hw_addr[6];
    unsigned char name[16];
    unsigned long config;
    unsigned long state;
    unsigned long curr;
    unsigned long advertised;
    unsigned long supported;
    unsigned long peer;
};

struct ofp_switch_features {
    unsigned long long datapath_id;
    unsigned long n_buffers;
    unsigned char n_tables;
    unsigned char pad[3];
    unsigned long capabilities;
    unsigned long actions;
    struct ofp_phy_port ports[];
};

struct ofp_packet_in {
  unsigned long buffer_id;
  unsigned short total_len;
  unsigned short in_port;
  unsigned char reason;
  unsigned char pad;
  struct ethernet_frame frame;
};

struct ethernet_frame {
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short type;
    unsigned char data[];
};

struct ofp_packet_out {
    unsigned long buffer_id;
    unsigned short in_port;
    unsigned short actions_len;
//    struct ofp_action_header actions[];
//    unsigned char data[];
};

struct ofp_action_header {
    unsigned short type;
    unsigned short len;
    unsigned char pad[4];
};

struct ofp_action_output {
    unsigned short type;
    unsigned short len;
    unsigned short port;
    unsigned short max_len;
};

struct ofp_switch_config {
    unsigned short flags;
    unsigned short miss_send_len;
};

