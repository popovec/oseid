
// types of KEY for fs_read_key/fs_write_key 
// (used low 5 bites, in upper bits reserved for flags)

#define KEY_OID		1
//EC key parts
#define KEY_EC_PRIVATE	2
#define KEY_EC_PUBLIC	3

// RSA key parts
// public exponent
#define KEY_RSA_EXP_PUB	0x81

// CRT components
#define KEY_RSA_p	0x83
#define KEY_RSA_q	0x84
#define KEY_RSA_dP	0x85
#define KEY_RSA_dQ	0x86
#define KEY_RSA_qInv	0x87
// modulus (for get data fcion.. not for CRT)
#define KEY_RSA_MOD	0x80
// parts for 2048 key
#define KEY_RSA_MOD_p1	0x88
#define KEY_RSA_MOD_p2	0x89

// not CRT parts private exponent full
#define KEY_RSA_EXP	0x82
// parts for 2048 key
#define KEY_RSA_EXP_p1	0x8a
#define KEY_RSA_EXP_p2	0x8b


// mask for key "generated"
#define KEY_GENERATE	0x40

#define KEY_FREE_SPACE 0xff

uint8_t get_rsa_key_part (void *here, uint8_t id);
