#define _GNU_SOURCE

#include <stdio.h>
#include "getline.c"		// We do this for getline support on platforms without glibc.
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/fips.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/x509v3.h>



/****************************************************************************************************
* Type definitions.                                                                                 *
****************************************************************************************************/

/*
*	This is a linked-list that deals exclusively with strings.
*/
struct StrLL {
	char				*str;	// The string.
	struct	StrLL	*next;	// The next element.
};


/*
*	A linked list.
*		The execd field carries this vector's state across operations. In order...
*			-3:	Vector was added by the execution of a prior Vector. DNE, but validate.
*			-2:	Vector is actually an answer key, and should not be executed.
*			0:	Vector is loaded and pending execution.
*			-1:	Vector failed to execute.
*			1:	Vector was executed and is pending validation.
*			2:	Vector was executed and it failed.
*			3:	Vector was executed and it passed.
*/
struct Vector {
	void*			content;		// The test vector itself. This MUST be the first member in this struct.
	struct StrLL*	flags;		// Used to store optional flags to be written to the response file.
	int				execd;		// Vector state.
	char*			name;		// The name of the test.
	struct Vector*	next;		// The next item in the list.
	char*			err;			// If there was an error of some sort, the reason will be stored here.
};


/*
*	A general container for tests.
*/
struct Test {
	char*				algo;
	char*				name;
	struct Test*			next;								// Reference to the next Test.
	struct Vector*		vector_list;							// Holds the root of a linked-list containing test vectors.
	struct Vector*		answer_key;							// Holds the root of a linked-list containing the correct answers.
	struct StrLL*		comment_list;						// Holds the root of a linked-list containing test commentary.
	int		(*exec_fxn)(struct Vector*);						// Function-pointer to execute a vector.
	void		(*print_fxn)(struct Vector*);						// Function-pointer to display a vector.
	void		(*dump_fxn)(struct Vector*, FILE *fp);				// Function-pointer to dump a vector to a file.
	int		(*parse_fxn)(struct Vector*);						// Function-pointer to parse lines from the test-def file.
	int		(*validate_fxn)(struct Vector*, struct Vector*);	// Function-pointer to validate this vector's results against the answer key.
	void		(*free_fxn)(struct Vector*);						// Function-pointer to un-allocate a vector.
};


/*
*	AES Vector definition...
*/
typedef struct {
	int						count;
	int						oper;				// 0 to ENCRYPT, 1 to DECRYPT.
	unsigned char*			key;
	int						key_len;
	unsigned char*			iv;
	int						iv_len;
	unsigned char*			plaintext;
	int						plaintext_len;
	unsigned char*			ciphertext;
	int						ciphertext_len;
	const EVP_CIPHER			*cipher_algo;
	int						key_size;
	int						block_mode;
} AESVector;


/*
*	ECDSA vector definition...
*/
typedef struct {
	int				n;
	unsigned char*	msg;
	int				msg_len;
	BIGNUM*			qx;
	BIGNUM*			qy;
	BIGNUM*			r;
	BIGNUM*			s;
	unsigned char*	result;
	unsigned long	result_code;
	char*			curve;
	int				curve_id;
	int				bit_depth;
	const EVP_MD		*digest;
} ECDSAVector;


/*
*	HMAC vector...
*/
typedef struct {
	int		count;
	int		l;
	int		k_len;
	int		t_len;
	unsigned char*	key;
	int				key_len;
	unsigned char*	msg;
	int				msg_len;
	unsigned char*	mac;
	int				mac_len;
} HMACVector;


/*
*	RNG Vector definition...
*/
typedef struct {
	int				count;
	unsigned char*	key;
	int				key_len;
	unsigned char*	dt;
	int				dt_len;
	unsigned char*	v;
	int				v_len;
	unsigned char*	r;
	int				r_len;
} RNGVector;


/*
*	A SHA vector looks like this...
*/
typedef struct {
	int				l;
	unsigned char*	md;
	int				md_len;
	int				len;		// Optional
	unsigned char*	msg;		// Optional
	int				msg_len;	// Optional
	unsigned char*	seed;		// Optional
	int				seed_len;	// Optional
	unsigned char*	chk_point[100];		// Optional: Monte Carlo check-points.
} SHAVector;


/****************************************************************************************************
* Function prototypes.                                                                              *
****************************************************************************************************/
char *trim(char *str);
void printBinString(unsigned char *str, int len);
void printBinStringToFile(unsigned char *str, int len, FILE *fp);
void printBinStringAsBin(unsigned char *str, int len);
void printBinStringAsBinToFile(unsigned char *str, int len, FILE *fp);
int parseStringIntoBytes(char* str, unsigned char* result);
void dumpTest(struct Test *test);

void printSHAVector(struct Vector *vector);
void dumpSHAVector(struct Vector *vector, FILE *fp);
int parseSHAVectorLine(SHAVector *item, char *line);
int validateSHAVector(struct Vector *vector, struct Vector*);
int PROC_SHA(struct Vector *vector);

void printECDSAVector(struct Vector *vector);
void dumpECDSAVector(struct Vector *vector, FILE *fp);
int parseECDSAVectorLine(ECDSAVector *item, char *line);
int validateECDSAVector(struct Vector *vector, struct Vector*);
int PROC_ECDSA(struct Vector *vector);

void printAESVector(struct Vector *vector);
void dumpAESVector(struct Vector *vector, FILE *fp);
int parseAESVectorLine(AESVector *item, char *line);
int validateAESVector(struct Vector *vector, struct Vector*);
int choose_aes_block_algo(AESVector *item, char *name);
int PROC_AES(struct Vector *vector);
int PROC_AES_MCT(struct Vector *vector);

void printRNGVector(struct Vector *vector);
void dumpRNGVector(struct Vector *vector, FILE *fp);
int parseRNGVectorLine(RNGVector *item, char *line);
int validateRNGVector(struct Vector *vector, struct Vector*);
int PROC_RNG(struct Vector *vector);

void printHMACVector(struct Vector *vector);
void dumpHMACVector(struct Vector *vector, FILE *fp);
int parseHMACVectorLine(HMACVector *item, char *line);
int validateHMACVector(struct Vector *vector, struct Vector*);
int PROC_HMAC(struct Vector *vector);

int buildTestVectors(char *test);
void listTest(struct Test *test);
void writeTestResults(struct StrLL *filter);
FILE* openResponseFile(struct Test *test);
int execTests(struct StrLL *filter);
void addVectorToTest(struct Test *test, void *vector, struct StrLL *flag);
struct Test* addTestToManifest(char* test, char* algo);
int parseTestsFromDir(struct StrLL *filter);
void printStatusLine(int code);
void troll(void);
void printHelp(void);


/****************************************************************************************************
* Globals and defines that make our life easier.                                                    *
****************************************************************************************************/
#define max(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

// gb(a, b) will return the b'th bit of a.
// sb(a, b, c) will set the b'th bit of a to the value c.
#define gb(a,b) (((a)[(b)/8] >> (7-(b)%8))&1)
#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << (7-(b)%8)))|(!!(v) << (7-(b)%8)))

#define	U_INPUT_BUFF_SIZE	64	// How big a buffer for user-input?
#define	AES_BLOCK_SIZE		16	// AES uses a 16-byte block size. Always.

#define	AES_CBC_BLOCK		0	// AES block-mode definitions.
#define	AES_ECB_BLOCK		1
#define	AES_OFB_BLOCK		2
#define	AES_CFB1_BLOCK		3
#define	AES_CFB8_BLOCK		4
#define	AES_CFB128_BLOCK		5

#define VERBOSE_ECDSA_ERR		0	// If set to 1, the ECDSA failures will be more verbose than CAVP requires.


char* enabled_tests[]	= {"AES", "RNG", "HMAC", "ECDSA", "SHA"};	// Which tests will we support?
char* test_root	= "./vector_root";					// Where are the tests located?

struct Test *root_node	= NULL;				// The root of the linked-list that holds the Tests.



/****************************************************************************************************
* Linked-list helper functions...                                                                   *
****************************************************************************************************/
/*
*	Inserts the nu Vector after the prev Vector. Maintains link integrity.
*/
int insertVectorAfterNode(struct Vector *nu, struct Vector *prev) {
	if (prev != NULL) {
		nu->next		= prev->next;
		prev->next	= nu;
		return 1;
	}
	return 0;
}


/*
*	Inserts the nu Vector at the end of the linked list of which head is a link.
*	Returns 1 on success, and 0 on failure. Should never return 0 if good parameters
*		are given.
*/
int insertVectorAtEnd(struct Vector *nu, struct Vector *head) {
	if (head != NULL) {
		struct Vector *temp	= head;
		while (temp->next != NULL) temp	= temp->next;
		temp->next	= nu;
		return 1;
	}
	return 0;
}


/**
* Helper fxn to get the length of all strings plus the delimiter. This is called before allocating
*	mem to flatten the string into a single multiline string.
*/
int totalStrLen(struct StrLL *root) {
	int len	= 0;
	if (root != NULL) {
		if (root->next != NULL) len	= 1 + totalStrLen(root->next);
		if (root->str != NULL) len	= (len + strlen(root->str));
	}
	return len;
}


struct StrLL* stackStrOntoList(struct StrLL *root, char *in) {
	if (root == NULL) {
		root	= malloc(sizeof(struct StrLL));
		root->next	= NULL;
		root->str	= strdup(in);
	}
	else root->next	= stackStrOntoList(root->next, in);
	return root;
}


/**
* Passed a root and a buffer, traverse the list and keep appending strings to
*	the buffer. It is the responsibility of the caller to ensure the buffer has
*	enough space for this to finish.
*/
void collapseIntoBuffer(struct StrLL *root, char *out) {
	if (root != NULL) {
		if (root->str != NULL) {
			strcat(out, root->str);
			if (root->next != NULL) {
				strcat(out, "\n");
				collapseIntoBuffer(root->next, out);
			}
		}
	}
}


/**
* Clean up after ourselves. Assumes that everything has been malloc'd into existance.
*/
void destroyStrLL(struct StrLL *r_node) {
	if (r_node != NULL) {
		if (r_node->next != NULL) {
			destroyStrLL(r_node->next);
			r_node->next	= NULL;
		}
		free(r_node->str);
		free(r_node->next);
		free(r_node);
	}
}


/**
* Returns a pointer to the relevant node if the given string loosly matches any of the strings in the list.
* Returns NULL if the string is not like any in the list.
*/
struct StrLL* is_str_loose_match(struct StrLL *root, char *test) {
	if (root == NULL) return NULL;
	if ((root->str != NULL) && (strcasestr(test, root->str))) return root; 
	return is_str_loose_match(root->next, test);
}



/****************************************************************************************************
* String manipulation functions.                                                                    *
****************************************************************************************************/

/*	Trim the whitespace from the beginning and end of the input string.
*	Should not be used on malloc'd space, because it will eliminate the
*		reference to the start of an allocated range which must be freed.
*/
char* trim(char *str){
	char *end;
	while(isspace(*str)) str++;
	if(*str == 0) return str;
	end = str + strlen(str) - 1;
	while(end > str && isspace(*end)) end--;
	*(end+1) = '\0';
	return str;
}


/*
*	Will interpret the given str as a sequence of bytes in hex.
*	Function parses the bytes (after left-padding for inputs with odd character counts) and
*		will write the resulting bytes into result. Returns the number of bytes so written.
*/
int parseStringIntoBytes(char* str, unsigned char* result) {
	int str_len	= strlen(str);
	char *temp_str	= alloca(str_len + 2);
	char *str_idx	= temp_str;
	bzero(temp_str, str_len + 2);
	if (str_len % 2 == 1) {		// Are there an odd number of digits?
		// If so, left-pad the string with a zero and pray.
		*str_idx	= '0';
		str_idx++;
	}
	memcpy(str_idx, str, str_len);		// Now copy the string into a temp space on the stack...
	str_len	= strlen(temp_str);

	int return_value	= str_len/2;
	char *sub_buf		= alloca(3);
	int i = 0;
	int n = 0;
	for (i = 0; i < (return_value*2); i=i+2) {
		bzero(sub_buf, 3);
		memcpy(sub_buf, (temp_str+i), 2);
		*(result + n++) = 0xFF & strtoul(sub_buf, NULL, 16);
	}
	return return_value;
}



/*
*	Compares two binary strings on a byte-by-byte basis.
*	Returns 1 if the values match. 0 otherwise.
*/
int cmpBinString(unsigned char *unknown, unsigned char *known, int len) {
	int i = 0;
	for (i = 0; i < len; i++) {
		if (*(unknown+i) != *(known+i)) return 0;
	}
	return 1;
}


/*
*	Writes the given bit string into a character buffer.
*/
char* printBitFieldToBuffer(unsigned char *str, int len, char *buffer) {
	if (buffer != NULL) {
		int i = 0;
		if ((str != NULL) && (len > 0)) {
			for (i = 0; i < len; i++) {
				if (*(str + (i/8)) & (0x80 >> i)) sprintf((buffer+i), "1");
				else sprintf((buffer+i), "0");
			}
		}
	}
	return buffer;
}


/*
*	Writes the given bit string into a character buffer.
*/
char* printBinStringToBuffer(unsigned char *str, int len, char *buffer) {
	if (buffer != NULL) {
	int i = 0;
		unsigned int moo	= 0;
		if ((str != NULL) && (len > 0)) {
			for (i = 0; i < len; i++) {
				moo	= *(str + i);
				sprintf((buffer+(i*2)), "%02x", moo);
			}
		}
	}
	return buffer;
}


/*
*	Reads a string into bytes.
*	Returns the number of _bits_ read
*/
int bint2bin(const char *in, unsigned char *out) {
	int	n = 0;
	int	len	= strlen(in);
	if (len % 8 > 0) n = 1;
	bzero(out, len/8+n);
	for(n = 0; n < len; ++n) {
		if (*(in+n) == '1') out[n/8] |= (0x80 >> (n % 8));
		else out[n/8] &= ~(0x80 >> (n % 8));
	}
	return n;
}


/*
*	Does a bit-by-bit comparison of the two buffers a and b. Compares
*		len bits and returns 1 if they are the same. Zero otherwise.
*/
int compareBitFields(unsigned char *a, unsigned char *b, int len) {
	int i;
	for (i = 0; i < len; i++) if ((*(a + (i/8)) & (0x80 >> (i%8))) != (*(b + (i/8)) & (0x80 >> (i%8)))) return 0;
	return 1;
}



/****************************************************************************************************
* Functions specific to SHA.                                                                        *
****************************************************************************************************/

/*
*	Create a new vector for SHA.
*/
SHAVector* INIT_VECTOR_SHA(char* name, int L, char* seed, int seed_len){
	SHAVector* active_vect = malloc(sizeof(SHAVector));
	active_vect->l			= L;
	active_vect->len			= -1;
	if (seed_len > 0) {
		active_vect->seed_len		= seed_len;
		active_vect->seed		= malloc(seed_len);
		memcpy(active_vect->seed, seed, seed_len); 		// This should have been malloc'd by the caller.
	}
	else {
		active_vect->seed_len		= 0;
		active_vect->seed		= NULL;
	}
	active_vect->md_len		= 0;
	active_vect->md			= NULL;
	active_vect->msg_len		= 0;
	active_vect->msg			= NULL;
	int i	= 0;
	for (i = 0; i < 100; i++) active_vect->chk_point[i]	= NULL;
	return active_vect;
}


/*
*	Calling this will free all the memory that was allocated to the given vector.
*/
void freeSHAVector(struct Vector *vector){
	SHAVector *vect	= (SHAVector*) vector->content;
	if (vect->seed_len > 0)	free(vect->seed);
	if (vect->md != NULL)		free(vect->md);
	if (vect->msg != NULL)	free(vect->msg);
	int i	= 0;
	for (i = 0; i < 100; i++) if (vect->chk_point[i] != NULL) free(vect->chk_point[i]);
}


/*
*	Validates the executed vector against the known-answer provided by CAVP.
*	Returns 2 on FAILURE and 3 on SUCCESS
*/
int validateSHAVector(struct Vector *vector, struct Vector *answer) {
	int return_value	= 2;		// Fail by default.
	if (vector->content != NULL) {
		SHAVector *test_vect	= (SHAVector*) vector->content;
		if (answer != NULL) {
			SHAVector *ans_vect	= (SHAVector*) answer->content;

			if (ans_vect->seed_len > 0) {		// Monte Carlo?
				int i	= 0;
				struct Vector *orig	= answer;
				for (i = 0; i < 100; i++) {
					if (cmpBinString(test_vect->chk_point[i], ans_vect->md, ans_vect->seed_len) == 0) {
						vector->execd	= return_value;
						return return_value;
					}
					answer	= answer->next;
					if (answer != NULL) ans_vect	= (SHAVector*) answer->content;
				}
				return_value		= 3;
			}
			else {
				if (test_vect->len == ans_vect->len) {
					if (test_vect->l == ans_vect->l) {
						if (test_vect->md_len == ans_vect->md_len) {
							if (test_vect->msg_len == ans_vect->msg_len) {
								if (test_vect->seed_len == ans_vect->seed_len) {
									if (cmpBinString(test_vect->md, ans_vect->md, ans_vect->md_len)) {
										if (cmpBinString(test_vect->msg, ans_vect->msg, ans_vect->msg_len)) {
											if (cmpBinString(test_vect->seed, ans_vect->seed, ans_vect->seed_len)) return_value	= 3;
											else printf("Test (%s) seed doesn't match.\n", vector->name);
										}
										else printf("Test (%s) MSG doesn't match.\n", vector->name);
									}
									else printf("Test (%s) MD doesn't match.\n", vector->name);
								}
								else printf("Test (%s) SEED length is different.\n", vector->name);
							}
							else printf("Test (%s) MSG length is different.\n", vector->name);
						}
						else printf("Test (%s) MD length is different.\n", vector->name);
					}
					else printf("Test (%s) L parameter is different.\n", vector->name);
				}
				else printf("Test (%s) LEN parameter doesn't match.\n", vector->name);
			}
		}
		else printf("Test (%s) doesn't have an answer key.\n", vector->name);
	}
	else printf("Test (%s) doesn't have a vector.\n", vector->name);
	vector->execd	= return_value;
	return return_value;
}


/*
*	Function writes response files for CAVP.
*/
void dumpSHAVector(struct Vector *vector, FILE *fp) {
	SHAVector *t_vect	= (SHAVector*) vector->content;
	if (vector->flags != NULL) {
		int		out_len	= totalStrLen(vector->flags);
		char*	output	= alloca(out_len);
		bzero(output, out_len);
		collapseIntoBuffer(vector->flags, output);
		fprintf(fp, "%s", output);
		fprintf(fp, "\n\n");
	}
	if (t_vect->seed_len > 0) {
		fprintf(fp, "Seed = ");
		printBinStringToFile(t_vect->seed, t_vect->seed_len, fp);
		fprintf(fp, "\n");
		int i = 0;
		for (i = 0; i < 100; i++) {
			fprintf(fp, "\nCOUNT = %d\n", i);
			fprintf(fp, "MD = ");
			printBinStringToFile(t_vect->chk_point[i], t_vect->seed_len, fp);
			fprintf(fp, "\n");
		}
	}
	else {
		if (t_vect->len > -1)	fprintf(fp, "LEN = %d\n", t_vect->len);

		if (t_vect->msg_len > 0) {
			fprintf(fp, "MSG = ");
			printBinStringToFile(t_vect->msg, t_vect->msg_len, fp);
			fprintf(fp, "\n");
		}

		if (t_vect->md_len > 0) {
			fprintf(fp, "MD = ");
			printBinStringToFile(t_vect->md, t_vect->md_len, fp);
			fprintf(fp, "\n");
		}
	}
	fprintf(fp, "\n");
}


/*
*	Function to dump an SHAVector to stdout.
*/
void printSHAVector(struct Vector *vector) {
	SHAVector *t_vect	= (SHAVector*) vector->content;
	printf("TEST:\t%s\n", vector->name);

	printStatusLine(vector->execd);
	if (vector->err != NULL) printf("ERROR:\t%s", vector->err);

	if (t_vect->l > -1)		printf("L:\t%d\n", t_vect->l);
	if (t_vect->len > -1)		printf("LEN:\t%d\n", t_vect->len);

	if (t_vect->seed_len > 0) {
		printf("SEED:\t");
		printBinString(t_vect->seed, t_vect->seed_len);
		printf("\n");
		int i = 0;
		for (i = 0; i < 100; i++) {
			printf("COUNT:\t%d\n", i);
			printf("MD:\t");
			printBinString(t_vect->chk_point[i], t_vect->seed_len);
			printf("\n");
		}
	}

	if (t_vect->msg_len > 0) {
		printf("MSG:\t");
		printBinString(t_vect->msg, t_vect->msg_len);
		printf("\n");
	}

	if (t_vect->md_len > 0) {
		printf("MD:\t");
		printBinString(t_vect->md, t_vect->md_len);
		printf("\n");
	}
	printf("\n");
}


int parseSHAVectorLine(SHAVector *item, char *line) {
	char *divider	= strchr(line, 0x3d);		// Find the KVP delimiter...
	if (divider == NULL) {
		return -1;
	}
	int key_len	= (divider - line);
	divider++;
	int val_len	= strlen(divider);

	char *key	= alloca(key_len+1);
	char *val	= alloca(val_len+1);
	bzero(key, key_len+1);
	bzero(val, val_len+1);
	memcpy(key, line, key_len);
	memcpy(val, divider, val_len);

	key = trim(key);
	val = trim(val);

	if (strcasecmp(key, "COUNT") == 0) {}
	else if (strcasecmp(key, "LEN") == 0) {
		item->len	= atoi(val);
	}
	else if (strcasecmp(key, "MSG") == 0) {
		item->msg		= malloc((strlen(val)/2)+1);
		item->msg_len	= parseStringIntoBytes(val, item->msg);
	}
	else if (strcasecmp(key, "MD") == 0) {
		item->md		= malloc((strlen(val)/2)+1);
		item->md_len	= parseStringIntoBytes(val, item->md);
	}
	else{
		printf("Unrecognized line (%s).\n", line);
	}
	return 0;
}


/*
*	The root of the SHA call.
*/
int PROC_SHA(struct Vector *vector) {
	SHAVector *t_vect	= (SHAVector*) vector->content;
	if (t_vect->seed_len > 0)			return PROC_SHA_MCT(vector);
	else if (t_vect->seed_len == 0)	return PROC_SHA_MSG(vector);
	else								return 0;
}


/*
*	Monte Carlo vectors get shunted to this function. These tests can be identified based on the
*		presence or absense of a seed value. The pseudocode in the FIPS doc is wrong. Don't use it.
*/
int PROC_SHA_MCT(struct Vector *vector) {
	int return_value	= 0;
	SHAVector *t_vect	= (SHAVector*) vector->content;
	
	const EVP_MD *evp_md		= NULL;

	if 		(strcasestr(vector->name, "SHA1") != NULL)		evp_md	= FIPS_evp_sha1();
	else if	(strcasestr(vector->name, "SHA224") != NULL)	evp_md	= FIPS_evp_sha224();
	else if	(strcasestr(vector->name, "SHA256") != NULL)	evp_md	= FIPS_evp_sha256();
	else if	(strcasestr(vector->name, "SHA384") != NULL)	evp_md	= FIPS_evp_sha384();
	else if	(strcasestr(vector->name, "SHA512") != NULL)	evp_md	= FIPS_evp_sha512();
	else {
		printf("Could not determine which hash algorithm to use. Failing test (%s)...\n", vector->name);
	}

	if (evp_md != NULL) {
		EVP_MD_CTX *cntxt = (EVP_MD_CTX *)(intptr_t) FIPS_md_ctx_create();

		unsigned char *Mx;
		int Mx_len	= 0;

		unsigned char *MD0	= alloca(t_vect->seed_len);
		unsigned char *MD1	= alloca(t_vect->seed_len);
		unsigned char *MD2	= alloca(t_vect->seed_len);

		int k = 0;
		for (k = 0; k < 100; k++) t_vect->chk_point[k]	= malloc(t_vect->seed_len);		// Alloc mem to the result set.

		memcpy(MD0, t_vect->seed, t_vect->seed_len);
		memcpy(MD1, t_vect->seed, t_vect->seed_len);
		memcpy(MD2, t_vect->seed, t_vect->seed_len);

		int i = 0;
		int j = 0;
		for (j = 0; j < 100; j++) {
			for (i = 0; i < 1000; i++) {
				FIPS_digestinit(cntxt, evp_md);
				FIPS_digestupdate(cntxt, MD0, t_vect->seed_len);
				FIPS_digestupdate(cntxt, MD1, t_vect->seed_len);
				FIPS_digestupdate(cntxt, MD2, t_vect->seed_len);
				Mx	= MD0;
				MD0	= MD1;
				MD1	= MD2;
				MD2	= Mx;
				FIPS_digestfinal(cntxt, MD2, &Mx_len);
			}
			memcpy(t_vect->chk_point[j], MD2, t_vect->seed_len);
			memcpy(MD0, MD2, t_vect->seed_len);
			memcpy(MD1, MD2, t_vect->seed_len);
		}
		FIPS_md_ctx_destroy(cntxt);
		return_value	= 1;
	}
	else {
		printf("Failed to load the digest algo for test (%s).\n", vector->name);
		return_value	= 0;
	}
	t_vect->md_len	= -1;
	return return_value;
}


/*
*	Perform a SHA digest.
*/
int PROC_SHA_MSG(struct Vector *vector){
	int return_value	= 0;
	SHAVector *t_vect	= (SHAVector*) vector->content;
	EVP_MD_CTX *cntxt;
	const EVP_MD *evp_md		= NULL;

	t_vect->md		= malloc(t_vect->l*2);
	t_vect->md_len	= t_vect->l;

	if 		(strcasestr(vector->name, "SHA1") != NULL)		evp_md	= FIPS_evp_sha1();
	else if	(strcasestr(vector->name, "SHA224") != NULL)	evp_md	= FIPS_evp_sha224();
	else if	(strcasestr(vector->name, "SHA256") != NULL)	evp_md	= FIPS_evp_sha256();
	else if	(strcasestr(vector->name, "SHA384") != NULL)	evp_md	= FIPS_evp_sha384();
	else if	(strcasestr(vector->name, "SHA512") != NULL)	evp_md	= FIPS_evp_sha512();
	else {
		printf("Could not determine which hash algorithm to use. Failing test (%s)...\n", vector->name);
	}

	if (evp_md != NULL) {
		cntxt = (EVP_MD_CTX *)(intptr_t) FIPS_md_ctx_create();
		FIPS_digestinit(cntxt, evp_md);
		if ((t_vect->msg_len > 0) && (t_vect->len > 0)) FIPS_digestupdate(cntxt, t_vect->msg, t_vect->msg_len);
		//FIPS_digest(t_vect->msg, t_vect->msg_len, t_vect->md, &t_vect->md_len, evp_md, NULL);
		FIPS_digestfinal(cntxt, t_vect->md, &t_vect->md_len);
		FIPS_md_ctx_destroy(cntxt);
		return_value	= 1;
	}
	else {
		printf("Failed to load the digest algo for test (%s).\n", vector->name);
		return_value	= 0;
	}
	return return_value;
}



/****************************************************************************************************
* Functions specific to ECDSA.                                                                      *
****************************************************************************************************/

/*
*	Create a new vector for ECDSA.
*/
ECDSAVector* INIT_VECTOR_ECDSA(char* curve){
	ECDSAVector* active_vect = malloc(sizeof(ECDSAVector));
	active_vect->n			= -1;
	active_vect->r			= NULL;
	active_vect->s			= NULL;
	active_vect->qx			= NULL;
	active_vect->qy			= NULL;
	active_vect->msg_len		= 0;
	active_vect->msg			= NULL;
	active_vect->curve		= strdup(curve);
	active_vect->curve_id		= -1;
	active_vect->bit_depth	= -1;
	active_vect->result_code	= -1;
	active_vect->result		= NULL;
	active_vect->digest		= NULL;
	return active_vect;
}


/*
*	Calling this will free all the memory that was allocated to the given vector.
*/
void freeECDSAVector(struct Vector *vector){
	ECDSAVector *vect	= (ECDSAVector*) vector->content;
	if (vect->msg != NULL)	free(vect->msg);
	//if (vect->curve != NULL)	printf("ABOUT TO FREE(%s) for %s\n", vect->curve, vector->name);
	if (vect->curve != NULL)	free(vect->curve);
	if (vect->result != NULL)	free(vect->result);

	// This is an EVP_MD...
	if (vect->digest != NULL)	{}

	// These are BIGNUMs...
	if (vect->r != NULL)		BN_free(vect->r);
	if (vect->s != NULL)		BN_free(vect->s);
	if (vect->qx != NULL)		BN_free(vect->qx);
	if (vect->qy != NULL)		BN_free(vect->qy);
	
	vect->result	= NULL;
	vect->curve	= NULL;
	vect->msg	= NULL;
	vect->r		= NULL;
	vect->s		= NULL;
	vect->qx		= NULL;
	vect->qy		= NULL;
}


/*
*	Validates the executed vector against the known-answer provided by CAVP.
*	Returns 2 on FAILURE and 3 on SUCCESS
*/
int validateECDSAVector(struct Vector *vector, struct Vector *answer) {
	int return_value	= 2;		// Fail by default.
	char *error	= alloca(256);
	bzero(error, 256);
	if (vector->content != NULL) {
		ECDSAVector *test_vect	= (ECDSAVector*) vector->content;
		
		if	(strcasestr(vector->name, "KEYPAIR"))	return_value	= 3;		// KEYPAIR is not a known-answer test.
		else if (answer != NULL) {
			ECDSAVector *ans_vect	= (ECDSAVector*) answer->content;
			if (test_vect->n == ans_vect->n) {
				if (cmpBinString(test_vect->msg, ans_vect->msg, ans_vect->msg_len)) {
					if (strcmp(test_vect->curve, ans_vect->curve) == 0) {

						if ((ans_vect->qx == NULL) || (BN_cmp(test_vect->qx, ans_vect->qx) == 0)) {
							if ((ans_vect->qy == NULL) || (BN_cmp(test_vect->qy, ans_vect->qy) == 0)) {
								if ((ans_vect->r == NULL) || (BN_cmp(test_vect->r, ans_vect->r) == 0)) {
									if ((ans_vect->s == NULL) || (BN_cmp(test_vect->s, ans_vect->s) == 0)) {
										if (ans_vect->result != NULL) {
											if (VERBOSE_ECDSA_ERR) {
												if (strcmp(test_vect->result, ans_vect->result) == 0) return_value	= 3;
												else sprintf(error, "RESULT is different. Expected (%s).\n", ans_vect->result);
											}
											else {
												if (test_vect->result[0] == ans_vect->result[0]) return_value	= 3;
												else sprintf(error, "RESULT is different. Expected (%c).\n", ans_vect->result[0]);
											}
										}
										else return_value = 3;
									}
									else sprintf(error, "S doesn't match. Expected ().\n");
								}
								else sprintf(error, "R doesn't match. Expected ().\n");
							}
							else sprintf(error, "Qy doesn't match. Expected ().\n");
						}
						else sprintf(error, "Qx doesn't match. Expected ().\n");
					}
					else sprintf(error, "Curves don't match. Expected (%s).\n", ans_vect->curve);
				}
				else sprintf(error, "MSG doesn't match. Expected ().\n");
			}
			else sprintf(error, "N parameter doesn't match. Expected (%d).\n", ans_vect->n);
		}
		else sprintf(error, "Test (%s) doesn't have an answer key.\n", vector->name);
	}
	else sprintf(error, "Test (%s) doesn't have a vector.\n", vector->name);
	vector->execd	= return_value;
	if (strlen(error) > 0) vector->err	= strdup(error);
	return return_value;
}


/*
*	Prints the given BIGNUM to the given FILE.
*	Ganked from OpenSSL.
*/
void do_bn_print_to_file(FILE *out, BIGNUM *bn) {
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	if (len == 0) fputs("00", out);
	else {
		tmp = alloca(len);
		BN_bn2bin(bn, tmp);
		for (i = 0; i < len; i++) fprintf(out, "%02x", tmp[i]);
	}
}


/*
*	Prints the given BIGNUM to STDIO.
*	Ganked from OpenSSL.
*/
void do_bn_print(BIGNUM *bn) {
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	if (len == 0) printf("00");
	else {
		tmp = alloca(len);
		BN_bn2bin(bn, tmp);
		for (i = 0; i < len; i++) printf("%02x", tmp[i]);
	}
}


/*
*	Function writes response files for CAVP.
*/
void dumpECDSAVector(struct Vector *vector, FILE *fp) {
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	if (vector->flags != NULL) {
		int		out_len	= totalStrLen(vector->flags);
		char*	output	= alloca(out_len);
		bzero(output, out_len);
		collapseIntoBuffer(vector->flags, output);
		fprintf(fp, "%s\n\n", output);
	}

	if (t_vect->msg_len > 0) {
		fprintf(fp, "Msg = ");
		printBinStringToFile(t_vect->msg, t_vect->msg_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->n > -1) fprintf(fp, "d = %d\n", t_vect->n);

	if (t_vect->qx != NULL) {
		fprintf(fp, "Qx = ");
		do_bn_print_to_file(fp, t_vect->qx);
		fprintf(fp, "\n");
	}

	if (t_vect->qy != NULL) {
		fprintf(fp, "Qy = ");
		do_bn_print_to_file(fp, t_vect->qy);
		fprintf(fp, "\n");
	}

	if (t_vect->r != NULL) {
		fprintf(fp, "R = ");
		do_bn_print_to_file(fp, t_vect->r);
		fprintf(fp, "\n");
	}
	if (t_vect->s != NULL) {
		fprintf(fp, "S = ");
		do_bn_print_to_file(fp, t_vect->s);
		fprintf(fp, "\n");
	}
	if (VERBOSE_ECDSA_ERR) {
		if ((t_vect->result != NULL) && (strlen(t_vect->result) > 0)) fprintf(fp, "Result = %s\n", t_vect->result);
	}
	else {
		if ((t_vect->result != NULL) && (strlen(t_vect->result) > 0)) fprintf(fp, "Result = %c\n", t_vect->result[0]);
	}
	fprintf(fp, "\n");
}


/*
*	Function to dump an Vector to stdout.
*/
void printECDSAVector(struct Vector *vector) {
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;

	printf("TEST:\t\t%s\n", vector->name);

	printStatusLine(vector->execd);
	if (vector->err != NULL) printf("ERROR:\t\t%s", vector->err);

	if (t_vect->n > -1) printf("N:\t\t%d\n", t_vect->n);

	if (t_vect->curve != NULL) printf("CURVE:\t\t%s\n", t_vect->curve);

	if (t_vect->result_code != -1) printf("ERR CODE:\t%ld\n", t_vect->result_code);

	if (t_vect->msg_len > 0) {
		printf("Msg:\t\t");
		printBinString(t_vect->msg, t_vect->msg_len);
		printf("\n");
	}

	if (t_vect->qx != NULL) {
		printf("Qx:\t\t");
		do_bn_print(t_vect->qx);
		printf("\n");
	}

	if (t_vect->qy != NULL) {
		printf("Qy:\t\t");
		do_bn_print(t_vect->qy);
		printf("\n");
	}

	if (t_vect->r != NULL) {
		printf("R:\t\t");
		do_bn_print(t_vect->r);
		printf("\n");
	}

	if (t_vect->s != NULL) {
		printf("S:\t\t");
		do_bn_print(t_vect->s);
		printf("\n");
	}

	printf("CURVEID:\t%d\n", t_vect->curve_id);

	if ((t_vect->result != NULL) && (strlen(t_vect->result) > 0)) printf("Result:\t\t%s\n", t_vect->result);
	printf("\n");
}



int parseECDSAVectorLine(ECDSAVector *item, char *line) {
	char *divider	= strchr(line, 0x3d);
	if (divider == NULL) {
		return -1;
	}
	int key_len	= (divider - line);
	divider++;
	int val_len	= strlen(divider);

	char *key	= alloca(key_len+1);
	char *val	= alloca(val_len+1);
	bzero(key, key_len+1);
	bzero(val, val_len+1);
	memcpy(key, line, key_len);
	memcpy(val, divider, val_len);

	key = trim(key);
	val = trim(val);

	if (strcasecmp(key, "N") == 0)			item->n			= atoi(val);
	else if (strcasecmp(key, "RESULT") == 0)	item->result		= strdup(val);

	else if (strcasecmp(key, "MSG") == 0) {
		item->msg		= malloc((strlen(val)/2)+1);
		item->msg_len	= parseStringIntoBytes(val, item->msg);
	}
	else if (strcasecmp(key, "QX") == 0) {
		if (!BN_hex2bn(&item->qx, val)) printf("Failed to parse Qx. %s\n", line);
	}
	else if (strcasecmp(key, "QY") == 0) {
		if (!BN_hex2bn(&item->qy, val)) printf("Failed to parse Qy. %s\n", line);
	}
	else if (strcasecmp(key, "R") == 0) {
		if (!BN_hex2bn(&item->r, val)) printf("Failed to parse R.\n");
	}
	else if (strcasecmp(key, "S") == 0) {
		if (!BN_hex2bn(&item->s, val)) printf("Failed to parse S.\n");
	}
	else {
		printf("Unrecognized line (%s).\n", line);
	}
	return 0;
}


/*
*	Call this to match the result code to the result string that CAVP expects...
*/
void match_ecdsa_response(struct Vector *vector) {
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	char *temp_str	= alloca(256);
	bzero(temp_str, 256);

	switch (t_vect->result_code) {
		case 354:
			sprintf(temp_str, "F (4 - Unhandled result code)");
			break;
		case 665:
			sprintf(temp_str, "F (4 - Q changed)");
			break;
		case 668:
			sprintf(temp_str, "F (1 - Message changed)");
			break;
		case 666:
			sprintf(temp_str, "F (2 - R changed)");
			break;
		case 667:
			sprintf(temp_str, "F (3 - S changed)");
			break;
		case 269160578:
			sprintf(temp_str, "F (2 - Added PT of order 2)");
			break;
		case 269160555:
			switch (t_vect->curve_id) {
				case NID_sect163r2:
				case NID_sect233r1:
				case NID_sect283r1:
				case NID_sect409r1:
				case NID_sect571r1:
				case NID_sect163k1:
				case NID_sect233k1:
				case NID_sect283k1:
				case NID_sect409k1:
				case NID_sect571k1:
					sprintf(temp_str, "F (1 - Point not on curve)");
					break;
				default:
					sprintf(temp_str, "F (2 - Point not on curve)");
					break;
			}
			break;
		case 269373586:
			sprintf(temp_str, "F (1 - Q_x or Q_y out of range)");
			break;
		case 0:
			sprintf(temp_str, "P (0 )");
			break;
		case -1:
			sprintf(temp_str, "");
			break;
		default:
			sprintf(temp_str, "UNHANDLED RESULT CODE (%ld). %s\n", t_vect->result_code, ERR_reason_error_string(t_vect->result_code));
			break;
	}
	t_vect->result	= strdup(temp_str);
}


/*
*	Given the name of the curve, set a pointer to the function in the vector.
*/
int get_ecdsa_curve_obj(struct Vector *vector) {
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	int return_value	= 1;
	if		(!strcasecmp(t_vect->curve, "B-163")) { t_vect->bit_depth = 163;	t_vect->curve_id	= NID_sect163r2;			}
	else if	(!strcasecmp(t_vect->curve, "B-233")) { t_vect->bit_depth = 233;	t_vect->curve_id	= NID_sect233r1;			}
	else if	(!strcasecmp(t_vect->curve, "B-283")) { t_vect->bit_depth = 283;	t_vect->curve_id	= NID_sect283r1;			}
	else if	(!strcasecmp(t_vect->curve, "B-409")) { t_vect->bit_depth = 409;	t_vect->curve_id	= NID_sect409r1;			}
	else if	(!strcasecmp(t_vect->curve, "B-571")) { t_vect->bit_depth = 571;	t_vect->curve_id	= NID_sect571r1;			}
	else if	(!strcasecmp(t_vect->curve, "K-163")) { t_vect->bit_depth = 163;	t_vect->curve_id	= NID_sect163k1;			}
	else if	(!strcasecmp(t_vect->curve, "K-233")) { t_vect->bit_depth = 233;	t_vect->curve_id	= NID_sect233k1;			}
	else if	(!strcasecmp(t_vect->curve, "K-283")) { t_vect->bit_depth = 283;	t_vect->curve_id	= NID_sect283k1;			}
	else if	(!strcasecmp(t_vect->curve, "K-409")) { t_vect->bit_depth = 409;	t_vect->curve_id	= NID_sect409k1;			}
	else if	(!strcasecmp(t_vect->curve, "K-571")) { t_vect->bit_depth = 571;	t_vect->curve_id	= NID_sect571k1;			}
	else if	(!strcasecmp(t_vect->curve, "P-192")) { t_vect->bit_depth = 192;	t_vect->curve_id	= NID_X9_62_prime192v1;	}
	else if	(!strcasecmp(t_vect->curve, "P-224")) { t_vect->bit_depth = 224;	t_vect->curve_id	= NID_secp224r1;			}
	else if	(!strcasecmp(t_vect->curve, "P-256")) { t_vect->bit_depth = 256;	t_vect->curve_id	= NID_X9_62_prime256v1;	}
	else if	(!strcasecmp(t_vect->curve, "P-384")) { t_vect->bit_depth = 384;	t_vect->curve_id	= NID_secp384r1;			}
	else if	(!strcasecmp(t_vect->curve, "P-521")) { t_vect->bit_depth = 521;	t_vect->curve_id	= NID_secp521r1;			}
	else {
		printf("Test %s has a bad curve name (%s).\n", vector->name, t_vect->curve);
		return_value	= 0;
	}

	if		(strcasestr(t_vect->curve, "SHA224") != NULL)	t_vect->digest	= FIPS_evp_sha224();
	else if	(strcasestr(t_vect->curve, "SHA256") != NULL)	t_vect->digest	= FIPS_evp_sha256();
	else if	(strcasestr(t_vect->curve, "SHA384") != NULL)	t_vect->digest	= FIPS_evp_sha384();
	else if	(strcasestr(t_vect->curve, "SHA512") != NULL)	t_vect->digest	= FIPS_evp_sha512();
	else if	(strcasestr(t_vect->curve, "SHA1") != NULL)	t_vect->digest	= FIPS_evp_sha1();
	else		t_vect->digest	= FIPS_evp_sha1();

	return return_value;
}


/*
*	The root of the  call.
*/
int PROC_ECDSA(struct Vector *vector) {
	int return_value	= -1;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	if (get_ecdsa_curve_obj(vector)) {	// Populate the test vector with the correct curve_id.
		// Decide what task we are to perform...
		if		(strcasestr(vector->name, "PKV"))		return_value	= PROC_ECDSA_PKV(vector);
		else if	(strcasestr(vector->name, "SIGGEN"))	return_value	= PROC_ECDSA_SIGGEN(vector);
		else if	(strcasestr(vector->name, "SIGVER"))	return_value	= PROC_ECDSA_SIGVER(vector);
		else if	(strcasestr(vector->name, "KEYPAIR"))	return_value	= PROC_ECDSA_KEYPAIR(vector);
		else {
			printf("Unknown ECDSA Test (%s).\n", vector->name);
		}
	}
	return return_value;
}


/*
*	If signature validation fails, we need to know what about the signature is bogus.
*		Returns an int. For all return values > 0, this will be a bitmask.
*		-1:	we experienced an error.
*		0:	no problem could be found.
*		1:	R != -S
*/
int discover_reason_for_failed_validation(struct Vector *vector) {
	int return_value	= 0;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *temp_bn0	= BN_new();
	BIGNUM *temp_bn1	= BN_new();

	BIGNUM *neg_s	= BN_dup(t_vect->s);
	BN_set_negative(neg_s, 1);

	printf("S*-1:\t\t");		do_bn_print(neg_s);	printf("\n");
	printf("R:\t\t");		do_bn_print(t_vect->r);	printf("\n");
	return_value	= return_value | 1;

	BN_free(temp_bn0);
	BN_free(temp_bn1);
	BN_free(neg_s);
	BN_CTX_free(ctx);
	return return_value;
}


int PROC_ECDSA_SIGVER(struct Vector *vector) {
	int return_value	= -1;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	while (ERR_get_error() != 0);		// Empty the error queue...

	EC_KEY *key		= (EC_KEY *)(intptr_t) FIPS_ec_key_new_by_curve_name(t_vect->curve_id);

	//ECDSA_SIG *w_sig	= alloca(sizeof(ECDSA_SIG));	// A working copy of the original.
	//ECDSA_SIG *w_sig	= FIPS_ecdsa_sig_new();
	ECDSA_SIG sg, *w_sig = &sg;
	w_sig->r = BN_dup(t_vect->r);
	w_sig->s = BN_dup(t_vect->s);

	BIGNUM *Qx	= BN_dup(t_vect->qx);
	BIGNUM *Qy	= BN_dup(t_vect->qy);

	if (key != NULL) {
			if (FIPS_ec_key_set_public_key_affine_coordinates(key, Qx, Qy) == 1) {
				int rv	= FIPS_ecdsa_verify(key, t_vect->msg, t_vect->msg_len, t_vect->digest, w_sig);
				if (rv != 1) {
					if (BN_cmp(w_sig->r, t_vect->r) != 0) {
						do_bn_print(t_vect->r);
						printf("\n");
						t_vect->result_code	= 666;
					}
					else if (BN_cmp(w_sig->s, t_vect->s) != 0) {
						do_bn_print(t_vect->s);
						printf("\n");
						t_vect->result_code	= 667;
					}
					else if ((BN_cmp(t_vect->qx, Qx) != 0) || (BN_cmp(t_vect->qy, Qy) != 0)) {
						do_bn_print(t_vect->r);
						printf("\n");
						t_vect->result_code	= 665;
					}
					else {
						t_vect->result_code		= 354;
					}
				}
				else t_vect->result_code	= 0;
			}
			else {
				t_vect->result_code		= ERR_peek_last_error();
			}
		return_value	= 1;
	}
	else printf("Failed to generate key for test (%s).\n", vector->name);

	FIPS_ec_key_free(key);                                  
	BN_free(Qx);
	BN_free(Qy);
	BN_free(w_sig->r);
	BN_free(w_sig->s);
	match_ecdsa_response(vector);
	return return_value;
}



int PROC_ECDSA_SIGGEN(struct Vector *vector) {
	int return_value	= -1;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	BIGNUM *Qx		= BN_new();
	BIGNUM *Qy		= BN_new();
	EC_KEY *key		= (EC_KEY *)(intptr_t) FIPS_ec_key_new_by_curve_name(t_vect->curve_id);
	ECDSA_SIG *sig	= NULL;
	const EVP_MD *digest = NULL;

	if (FIPS_ec_key_generate_key(key)) {
		if (ec_get_pubkey(key, Qx, Qy)) {
			sig = (ECDSA_SIG *)(intptr_t) FIPS_ecdsa_sign(key, t_vect->msg, t_vect->msg_len, t_vect->digest);
			t_vect->qx	= Qx;
			t_vect->qy	= Qy;
			t_vect->r	= sig->r;
			t_vect->s	= sig->s;
		}
		else {
			t_vect->result_code		= ERR_peek_last_error();
			printf("Failed to obtain public key for test (%s).\n", vector->name);
		}
		return_value	= 1;
	}
	else printf("Failed to generate key for test (%s).\n", vector->name);

	FIPS_ec_key_free(key);
	return return_value;
}



/*
*	Public Key Verification
*/
int PROC_ECDSA_PKV(struct Vector *vector) {
	int return_value	= -1;
	int rv	= 0;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;

	while (ERR_get_error() != 0);		// Empty the error queue...

	EC_KEY *key	= (EC_KEY *)(intptr_t) FIPS_ec_key_new_by_curve_name(t_vect->curve_id);		// Let's make a slot for a key on this curve...

	if (key != NULL) {
		if (rv = FIPS_ec_key_set_public_key_affine_coordinates(key, t_vect->qx, t_vect->qy) == 1) {		// Set the public key...
			t_vect->result_code	= 0;
		}
		else {		// Figure out what went wrong....
			t_vect->result_code		= ERR_peek_last_error();

			BN_CTX *ctx = BN_CTX_new();
			BIGNUM *temp_bn0	= BN_new();
			BIGNUM *temp_bn1	= BN_new();
			BIGNUM *temp_bn2	= BN_new();
			BIGNUM *temp_bn3	= BN_new();
			const EC_GROUP *grp	 	= (EC_GROUP *)(intptr_t) FIPS_ec_key_get0_group(key);
			EC_GROUP_get_order(grp, temp_bn0, ctx);
			EC_GROUP_get_cofactor(grp, temp_bn1, ctx);
			BN_div(temp_bn2, temp_bn3, temp_bn0, temp_bn1, ctx);

			BN_free(temp_bn0);
			BN_free(temp_bn1);
			BN_free(temp_bn2);
			BN_free(temp_bn3);
			BN_CTX_free(ctx);
		}
		FIPS_ec_key_free(key);
		return_value	= 1;
	}
	else {
		printf("%s:\tError (%s) given by FIPS_ec_key_new_by_curve_name().\n", vector->name, ERR_reason_error_string(ERR_peek_last_error()));
	}

	match_ecdsa_response(vector);
	return return_value;
}



/*
*	Ganked from OpenSSL, and then modified for better error-checking with expanded return states.
*	Returns...
*		-2 if the point is not on the curve.
*		-3 if the point is at infinity.
*/
int ec_get_pubkey(EC_KEY *key, BIGNUM *x, BIGNUM *y) {
	int rv;
	BN_CTX *ctx = BN_CTX_new();

	if (!ctx) return 0;
	const EC_GROUP *grp	 	= (EC_GROUP *)(intptr_t) FIPS_ec_key_get0_group(key);
	const EC_POINT *pt		= (EC_POINT *)(intptr_t) FIPS_ec_key_get0_public_key(key);
	if (!FIPS_ec_point_is_on_curve(grp, pt, ctx)) {
		printf("Point is not on curve.\n");
		rv = -2;
	}
	else if (FIPS_ec_point_is_at_infinity(grp, pt)) {
		printf("Point is not on curve.\n");
		rv = -3;
	}
	else {
		const EC_METHOD *meth		= (EC_METHOD *)(intptr_t) FIPS_ec_group_method_of(grp);
		if (FIPS_ec_method_get_field_type(meth) == NID_X9_62_prime_field) {
			rv = FIPS_ec_point_get_affine_coordinates_gfp(grp, pt, x, y, ctx);
		}
		else {
			rv = FIPS_ec_point_get_affine_coordinates_gf2m(grp, pt, x, y, ctx);
		}
	}

	BN_CTX_free(ctx);
	return rv;
}


/**
*	KeyPair test will generate new vectors. There are no known-answers for this test.
*/
int PROC_ECDSA_KEYPAIR(struct Vector *vector) {
	int return_value	= -1;
	ECDSAVector *t_vect	= (ECDSAVector*) vector->content;
	
	if ((t_vect->qx == NULL) && (t_vect->qy == NULL)) {
		BIGNUM *Qx		= NULL;
		BIGNUM *Qy		= NULL;
		EC_KEY *key		= NULL;
		ECDSAVector *nu_vect	= NULL;
		struct Vector *nu_vector		= NULL;
		struct Vector *ptr_vector		= vector;
		
		int curve_id	= t_vect->curve_id;
		int i;
		int end	= t_vect->n;
		for (i = 1; i <= end; i++) {
			Qx	= BN_new();
			Qy	= BN_new();
	
			key = (EC_KEY *)(intptr_t) FIPS_ec_key_new_by_curve_name(curve_id);
			if (FIPS_ec_key_generate_key(key)) {
				if (ec_get_pubkey(key, Qx, Qy)) {                          
					if (i != 1) {		// If this is not our initial vector...
						nu_vect				= INIT_VECTOR_ECDSA(t_vect->curve);			// Create the new ECDSA Vector...
						nu_vect->curve_id	= curve_id;									// Which curve?
						nu_vect->result_code	= 0;
						nu_vect->qx	= Qx;
						nu_vect->qy	= Qy;
						nu_vect->n	= i;
						nu_vector	= malloc(sizeof(struct Vector));						// ...create the container...
						nu_vector->content	= nu_vect;									// ...assign the vect to it...
						nu_vector->name		= strdup(vector->name);						// ...label it with the test name...
						nu_vector->execd		= -3;										// ...mark it as AWAITING VALIDATION...
						nu_vector->err		= NULL;
						nu_vector->flags		= NULL;
						if (!insertVectorAfterNode(nu_vector, ptr_vector)) printf("ERROR INSERTING new test vector for Test (%s).\n", vector->name);	// ...and append it to our list.
						ptr_vector	= nu_vector;
					}
					else {
						t_vect->result_code	= 0;
						t_vect->qx	= Qx;
						t_vect->qy	= Qy;
						t_vect->n	= i;
					}

					return_value	= 1;
				}
				else {
					printf("Failed to obtain public key for test (%s).\n", vector->name);
					t_vect->result_code		= ERR_get_error();
				}
				FIPS_ec_key_free(key);
			}
			else printf("Failed to generate key for test (%s).\n", vector->name);
		}
	}
	return return_value;
}


/****************************************************************************************************
* Functions specific to RNG.                                                                        *
****************************************************************************************************/

/*
*	Create a new vector for RNG.
*/
RNGVector* INIT_VECTOR_RNG(char* name, int key_size, char* standard){
	RNGVector* active_vect = malloc(sizeof(RNGVector));
	active_vect->count		= -1;
	active_vect->v_len		= 0;
	active_vect->v			= NULL;
	active_vect->r_len		= 0;
	active_vect->r			= NULL;
	active_vect->dt_len		= 0;
	active_vect->dt			= NULL;
	active_vect->key_len		= 0;
	active_vect->key			= NULL;
	return active_vect;
}


/*
*	Calling this will free all the memory that was allocated to the given vector.
*/
void freeRNGVector(struct Vector *vector){
	RNGVector *vect	= (RNGVector*) vector->content;
	if (vect->v != NULL)		free(vect->v);
	if (vect->r != NULL)		free(vect->r);
	if (vect->dt != NULL)		free(vect->dt);
	if (vect->key != NULL)	free(vect->key);
}


/*
*	Validates the executed vector against the known-answer provided by CAVP.
*	Returns 2 on FAILURE and 3 on SUCCESS
*/
int validateRNGVector(struct Vector *vector, struct Vector *answer) {
	int return_value	= 2;		// Fail by default.
	if (vector->content != NULL) {
		RNGVector *test_vect	= (RNGVector*) vector->content;
		if (answer != NULL) {
			RNGVector *ans_vect	= (RNGVector*) answer->content;
			if (test_vect->count == ans_vect->count) {
				if (test_vect->key_len == ans_vect->key_len) {
					if (test_vect->r_len == ans_vect->r_len) {
						if (test_vect->v_len == ans_vect->v_len) {
							if (test_vect->dt_len == ans_vect->dt_len) {
								if (cmpBinString(test_vect->v, ans_vect->v, ans_vect->v_len)) {
									if (cmpBinString(test_vect->r, ans_vect->r, ans_vect->r_len)) {
										if (cmpBinString(test_vect->dt, ans_vect->dt, ans_vect->dt_len)) {
											if (cmpBinString(test_vect->key, ans_vect->key, ans_vect->key_len)) return_value	= 3;
											else printf("Test (%s) key doesn't match.\n", vector->name);
										}
										else printf("Test (%s) DT doesn't match.\n", vector->name);
									}
									else printf("Test (%s) R doesn't match.\n", vector->name);
								}
								else printf("Test (%s) V doesn't match.\n", vector->name);
							}
							else printf("Test (%s) DT length is different.\n", vector->name);
						}
						else printf("Test (%s) V length is different.\n", vector->name);
					}
					else printf("Test (%s) R length is different.\n", vector->name);
				}
				else printf("Test (%s) KEY length is different.\n", vector->name);
			}
			else printf("Test (%s) COUNT parameter doesn't match.\n", vector->name);
		}
		else printf("Test (%s) doesn't have an answer key.\n", vector->name);
	}
	else printf("Test (%s) doesn't have a vector.\n", vector->name);
	vector->execd	= return_value;
	return return_value;
}


/*
*	Function writes response files for CAVP.
*/
void dumpRNGVector(struct Vector *vector, FILE *fp) {
	RNGVector *t_vect	= (RNGVector*) vector->content;
	if (vector->flags != NULL) {
		int		out_len	= totalStrLen(vector->flags);
		char*	output	= alloca(out_len);
		bzero(output, out_len);
		collapseIntoBuffer(vector->flags, output);
		fprintf(fp, "%s", output);
		fprintf(fp, "\n\n");
	}

	fprintf(fp, "COUNT = %d\n", t_vect->count);

	if (t_vect->key_len > 0) {
		fprintf(fp, "KEY = ");
		printBinStringToFile(t_vect->key, t_vect->key_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->dt_len > 0) {
		fprintf(fp, "DT = ");
		printBinStringToFile(t_vect->dt, t_vect->dt_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->v_len > 0) {
		fprintf(fp, "V = ");
		printBinStringToFile(t_vect->v, t_vect->v_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->r_len > 0) {
		fprintf(fp, "R = ");
		printBinStringToFile(t_vect->r, t_vect->r_len, fp);
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
}


/*
*	Function to dump an RNGVector to stdout.
*/
void printRNGVector(struct Vector *vector) {
	RNGVector *t_vect	= (RNGVector*) vector->content;

	printStatusLine(vector->execd);
	if (vector->err != NULL) printf("ERROR:\t\t%s", vector->err);

	printf("COUNT:\t\t%d\n", t_vect->count);

	if (t_vect->key_len > 0) {
		printf("KEY:\t");
		printBinString(t_vect->key, t_vect->key_len);
		printf("\n");
	}

	if (t_vect->dt_len > 0) {
		printf("DT:\t");
		printBinString(t_vect->dt, t_vect->dt_len);
		printf("\n");
	}

	if (t_vect->v_len > 0) {
		printf("V:\t");
		printBinString(t_vect->v, t_vect->v_len);
		printf("\n");
	}

	if (t_vect->r_len > 0) {
		printf("R:\t");
		printBinString(t_vect->r, t_vect->r_len);
		printf("\n");
	}
	printf("\n");
}


int parseRNGVectorLine(RNGVector *item, char *line) {
	char *divider	= strchr(line, 0x3d);
	if (divider == NULL) {
		return -1;
	}
	int key_len	= (divider - line);
	divider++;
	int val_len	= strlen(divider);

	char *key	= alloca(key_len+1);
	char *val	= alloca(val_len+1);
	bzero(key, key_len+1);
	bzero(val, val_len+1);
	memcpy(key, line, key_len);
	memcpy(val, divider, val_len);

	key = trim(key);
	val = trim(val);

	if (strcasecmp(key, "COUNT") == 0) item->count	= atoi(val);
	else if (strcasecmp(key, "KEY") == 0) {
		item->key		= malloc((strlen(val)/2)+1);
		item->key_len	= parseStringIntoBytes(val, item->key);
	}
	else if (strcasecmp(key, "DT") == 0) {
		item->dt		= malloc((strlen(val)/2)+1);
		item->dt_len	= parseStringIntoBytes(val, item->dt);
	}
	else if (strcasecmp(key, "V") == 0) {
		item->v		= malloc((strlen(val)/2)+1);
		item->v_len	= parseStringIntoBytes(val, item->v);
	}
	else if (strcasecmp(key, "R") == 0) {
		item->r		= malloc((strlen(val)/2)+1);
		item->r_len	= parseStringIntoBytes(val, item->r);
	}
	else{
		printf("Unrecognized line (%s).\n", line);
	}
	return 0;
}


/*
*	The root of the RNG call.
*/
int PROC_RNG(struct Vector *vector) {
	RNGVector *t_vect	= (RNGVector*) vector->content;
	if (strcasestr(vector->name, "MCT") != NULL)		return PROC_RNG_MCT(t_vect);
	else if (strcasestr(vector->name, "VST") != NULL)	return PROC_RNG_VST(t_vect);
	else												return 0;
}



/*
*	Monte Carlo vectors get shunted to this function. Unlike the SHA vectors, these tests don't use seeds.
*		instead, we've relied on the file name to tell us how to treat the parameters that are otherwise
*		identical.
*/
int PROC_RNG_MCT(RNGVector *vector) {
	int return_value	= 0;
	unsigned char *ret	= alloca(16);
	unsigned char *dt	= alloca(vector->dt_len);			// An intermediate value.
	unsigned char *I		= alloca(AES_BLOCK_SIZE);			// An intermediate value.
	unsigned char *V		= alloca(AES_BLOCK_SIZE);			// An intermediate value.
	unsigned char *tI	= alloca(AES_BLOCK_SIZE);			// An temporary intermediate value. (Very intermediate)
	int i, j, n;
	vector->r_len 	= AES_BLOCK_SIZE;			// The result will always be 16 bytes long.
	vector->r		= malloc(vector->r_len);	// Allocate 16 bytes for the result.

	memcpy(dt, vector->dt, vector->dt_len);
	memcpy(V, vector->v, vector->v_len);

	EVP_CIPHER_CTX en_ctx;
	const EVP_CIPHER	*ciph;
	switch (vector->key_len) {		// How big is the AES key?
		case 32:	// AES-256
			ciph	= FIPS_evp_aes_256_ecb();
			break;
		case 24:	// AES-192
			ciph	= FIPS_evp_aes_192_ecb();
			break;
		case 16:	// AES-128
			ciph	= FIPS_evp_aes_128_ecb();
			break;
		default:
			printf("PROC_RNG_MCT() is not sure what to do with a key length of (%d).\n", vector->key_len);
			return -1;
	}

	EVP_CIPHER_CTX_init(&en_ctx);
	EVP_EncryptInit_ex(&en_ctx, ciph, NULL, vector->key, NULL);
	for (i = 0; i < 10000; i++) {
		EVP_EncryptUpdate(&en_ctx, I, &n, dt, vector->dt_len);
		for (j = 0; j < 16; j++) *(tI + j) = *(I + j) ^ *(V + j);
		EVP_EncryptUpdate(&en_ctx, ret, &n, tI, vector->dt_len);

		// We ought to generate a new V.
		for (j = 0; j < 16; j++) *(tI + j) = *(I + j) ^ *(ret + j);
		EVP_EncryptUpdate(&en_ctx, V, &n, tI, vector->dt_len);

		// Increment DT. There is a great deal of fail out there on the internet. This is the *correct* way.
		for (j = 15; j > 0; j--) {
			dt[j]++;
			if (dt[j] != 0) break;
		}
	}
	EVP_CIPHER_CTX_cleanup(&en_ctx);
	memcpy(vector->r, ret, vector->r_len);		// Copy the final value back to the vector.
	return_value	= 1;
	return return_value;
}


/*
*	Variable seed test vector.
*	Output for this test will always be 16-bytes (one AES block).
*/
int PROC_RNG_VST(RNGVector *vector){
	int return_value	= 0;
    int aes_block_size	= 16;				// This may need to be dynamically-read from the test.
	EVP_CIPHER_CTX en_ctx;
	const EVP_CIPHER	*ciph;
	switch (vector->key_len) {		// How big is the AES key?
		case 32:	// AES-256
			ciph	= FIPS_evp_aes_256_ecb();
			break;
		case 24:	// AES-192
			ciph	= FIPS_evp_aes_192_ecb();
			break;
		case 16:	// AES-128
			ciph	= FIPS_evp_aes_128_ecb();
			break;
		default:
			printf("PROC_RNG_VST() is not sure what to do with a key length of (%d).\n", vector->key_len);
			return -1;
	}

    EVP_CIPHER_CTX_init(&en_ctx);
    EVP_EncryptInit_ex(&en_ctx, ciph, NULL, vector->key, NULL);

    vector->r		= malloc(aes_block_size);	// Allocate 16 bytes for the result.
    vector->r_len = aes_block_size;			// The result will always be 16 bytes long.
    unsigned char *I	= alloca(16);			// An intermediate value.
    unsigned char *tI	= alloca(16);			// An temporary intermediate value. (Very intermediate)
    int i = 0;

    if (vector->r != NULL) {
		EVP_EncryptInit_ex(&en_ctx, NULL, NULL, NULL, NULL);
		EVP_EncryptUpdate(&en_ctx, I, &aes_block_size, (unsigned char *)vector->dt, vector->dt_len);
		for (i = 0; i < 16; i++) *(tI + i) = *(I + i) ^ *(vector->v + i);
		EVP_EncryptUpdate(&en_ctx, vector->r, &aes_block_size, (unsigned char *)tI, vector->dt_len);

		// We ought to generate a new V.
		for (i = 0; i < 16; i++) *(tI + i) = *(I + i) ^ *(vector->r + i);
		EVP_CIPHER_CTX_cleanup(&en_ctx);
		return_value	= 1;
	}
	else {
		printf("Couldn't allocate memory for encryption.\n");
		EVP_CIPHER_CTX_cleanup(&en_ctx);
		return -1;
	}
	return return_value;
}



/****************************************************************************************************
* Functions specific to HMAC.                                                                       *
****************************************************************************************************/

/*
*	Create a new vector for HMAC.
*/
HMACVector* INIT_VECTOR_HMAC(char* name, int len){
	HMACVector* active_vect = malloc(sizeof(HMACVector));
	active_vect->l			= len;
	active_vect->count		= -1;
	active_vect->k_len		= -1;
	active_vect->t_len		= -1;
	active_vect->msg_len	= 0;
	active_vect->msg		= NULL;
	active_vect->mac_len	= 0;
	active_vect->mac		= NULL;
	active_vect->key_len	= 0;
	active_vect->key		= NULL;
	return active_vect;
}


/*
*	Calling this will free all the memory that was allocated to the given vector.
*/
void freeHMACVector(struct Vector *vector){
	HMACVector *vect	= (HMACVector*) vector->content;
	if (vect->msg != NULL)	free(vect->msg);
	if (vect->mac != NULL)	free(vect->mac);
	if (vect->key != NULL)	free(vect->key);
}


/*
*	Validates the executed vector against the known-answer provided by CAVP.
*	Returns 2 on FAILURE and 3 on SUCCESS
*/
int validateHMACVector(struct Vector *vector, struct Vector *answer) {
	int return_value	= 2;		// Fail by default.
	if (vector->content != NULL) {
		HMACVector *test_vect	= (HMACVector*) vector->content;
		if (answer != NULL) {
			HMACVector *ans_vect	= (HMACVector*) answer->content;
			if (test_vect->count == ans_vect->count) {
				if (test_vect->l == ans_vect->l) {
					if (test_vect->k_len == ans_vect->k_len) {
						if (test_vect->t_len == ans_vect->t_len) {
							if (test_vect->msg_len == ans_vect->msg_len) {
								if (test_vect->mac_len == ans_vect->mac_len) {
									if (test_vect->key_len == ans_vect->key_len) {
										if (cmpBinString(test_vect->mac, ans_vect->mac, ans_vect->mac_len)) {
											if (cmpBinString(test_vect->msg, ans_vect->msg, ans_vect->msg_len)) {
												if (cmpBinString(test_vect->key, ans_vect->key, ans_vect->key_len)) return_value	= 3;
												else printf("Test (%s) key doesn't match.\n", vector->name);
											}
											else printf("Test (%s) MSG doesn't match.\n", vector->name);
										}
										else printf("Test (%s) MAC doesn't match.\n", vector->name);
									}
									else printf("Test (%s) KEY length is different.\n", vector->name);
								}
								else printf("Test (%s) MAC length is different.\n", vector->name);
							}
							else printf("Test (%s) MSG length is different.\n", vector->name);
						}
						else printf("Test (%s) T length is different.\n", vector->name);
					}
					else printf("Test (%s) K length is different.\n", vector->name);
				}
				else printf("Test (%s) L is different.\n", vector->name);
			}
			else printf("Test (%s) COUNT parameter doesn't match.\n", vector->name);
		}
		else printf("Test (%s) doesn't have an answer key.\n", vector->name);
	}
	else printf("Test (%s) doesn't have a vector.\n", vector->name);
	vector->execd	= return_value;
	return return_value;
}


/*
*	Function writes response files for CAVP.
*/
void dumpHMACVector(struct Vector *vector, FILE *fp) {
	HMACVector *t_vect	= (HMACVector*) vector->content;
	if (vector->flags != NULL) {
		int		out_len	= totalStrLen(vector->flags);
		char*	output	= alloca(out_len);
		bzero(output, out_len);
		collapseIntoBuffer(vector->flags, output);
		fprintf(fp, "%s", output);
		fprintf(fp, "\n\n");
	}

	fprintf(fp, "Count = %d\n", t_vect->count);
	fprintf(fp, "Klen = %d\n", t_vect->k_len);
	fprintf(fp, "Tlen = %d\n", t_vect->t_len);

	if (t_vect->key_len > 0) {
		fprintf(fp, "Key = ");
		printBinStringToFile(t_vect->key, t_vect->key_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->msg_len > 0) {
		fprintf(fp, "Msg = ");
		printBinStringToFile(t_vect->msg, t_vect->msg_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->mac_len > 0) {
		fprintf(fp, "Mac = ");
		printBinStringToFile(t_vect->mac, t_vect->mac_len, fp);
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
}


/*
*	Function to dump an HMACVector to stdout.
*/
void printHMACVector(struct Vector *vector) {
	HMACVector *t_vect	= (HMACVector*) vector->content;

	printf("TEST:\t%s\n", vector->name);
	printStatusLine(vector->execd);
	if (vector->err != NULL) printf("ERROR:\t%s", vector->err);

	printf("COUNT:\t\t%d\n", t_vect->count);
	printf("Klen:\t\t%d\n", t_vect->k_len);
	printf("Tlen:\t\t%d\n", t_vect->t_len);

	if (t_vect->key_len > 0) {
		printf("KEY:\t");
		printBinString(t_vect->key, t_vect->key_len);
		printf("\n");
	}

	if (t_vect->msg_len > 0) {
		printf("Msg:\t");
		printBinString(t_vect->msg, t_vect->msg_len);
		printf("\n");
	}

	if (t_vect->mac_len > 0) {
		printf("Mac:\t");
		printBinString(t_vect->mac, t_vect->mac_len);
		printf("\n");
	}
	printf("\n");
}


int parseHMACVectorLine(HMACVector *item, char *line) {
	char *divider	= strchr(line, 0x3d);
	if (divider == NULL) return -1;

	int key_len	= (divider - line);
	divider++;
	int val_len	= strlen(divider);

	char *key	= alloca(key_len+1);
	char *val	= alloca(val_len+1);
	bzero(key, key_len+1);
	bzero(val, val_len+1);
	memcpy(key, line, key_len);
	memcpy(val, divider, val_len);

	key = trim(key);
	val = trim(val);

	if		(strcasecmp(key, "COUNT") == 0) 	item->count	= atoi(val);
	else if	(strcasecmp(key, "KLEN") == 0)		item->k_len	= atoi(val);
	else if	(strcasecmp(key, "TLEN") == 0)		item->t_len	= atoi(val);

	else if (strcasecmp(key, "KEY") == 0) {
		item->key		= malloc((strlen(val)/2)+1);
		item->key_len	= parseStringIntoBytes(val, item->key);
	}
	else if (strcasecmp(key, "MSG") == 0) {
		item->msg		= malloc((strlen(val)/2)+1);
		item->msg_len	= parseStringIntoBytes(val, item->msg);
	}
	else if (strcasecmp(key, "MAC") == 0) {
		item->mac		= malloc((strlen(val)/2)+1);
		item->mac_len	= parseStringIntoBytes(val, item->mac);
	}
	else printf("Unrecognized line (%s).\n", line);
	return 0;
}


/*
*	The root of the HMAC call.
*/
int PROC_HMAC(struct Vector *vector) {
	HMACVector *t_vect	= (HMACVector*) vector->content;
	const EVP_MD	*hash_fxn;

	int temp_len	= 0;
	unsigned char* temp	= alloca(t_vect->t_len*2);

	switch (t_vect->l) {
		case 20:
			hash_fxn	= FIPS_evp_sha1();
			break;
		case 28:
			hash_fxn	= FIPS_evp_sha224();
			break;
		case 32:
			hash_fxn	= FIPS_evp_sha256();
			break;
		case 48:
			hash_fxn	= FIPS_evp_sha384();
			break;
		case 64:
			hash_fxn	= FIPS_evp_sha512();
			break;
	}

	t_vect->mac	= malloc(t_vect->t_len);
	HMAC_CTX ctx;
	FIPS_hmac_ctx_init(&ctx);
	FIPS_hmac_init_ex(&ctx, t_vect->key, t_vect->key_len, hash_fxn, NULL);
	FIPS_hmac_update(&ctx, t_vect->msg, t_vect->msg_len);
	FIPS_hmac_final(&ctx, temp, &temp_len);
	FIPS_hmac_ctx_cleanup(&ctx);

	memcpy(t_vect->mac, temp, t_vect->t_len);
	t_vect->mac_len	= t_vect->t_len;
	return 1;
}


/****************************************************************************************************
* Functions specific to AES.                                                                        *
****************************************************************************************************/

/*
*	Create a new vector for AES.
*/
AESVector* INIT_VECTOR_AES(int enc_dec){
	AESVector* active_vect = malloc(sizeof(AESVector));
	active_vect->block_mode		= -1;
	active_vect->oper			= enc_dec;
	active_vect->iv_len			= 0;
	active_vect->iv				= NULL;
	active_vect->key_len			= 0;
	active_vect->key				= NULL;
	active_vect->ciphertext_len	= 0;
	active_vect->ciphertext		= NULL;
	active_vect->plaintext_len	= 0;
	active_vect->plaintext		= NULL;
	return active_vect;
}


/*
*	Calling this will free all the memory that was allocated to the given vector.
*/
void freeAESVector(struct Vector *vector){
	AESVector *vect	= (AESVector*) vector->content;
	if (vect->iv != NULL)			free(vect->iv);
	if (vect->key != NULL)		free(vect->key);
	if (vect->ciphertext != NULL)	free(vect->ciphertext);
	if (vect->plaintext != NULL)	free(vect->plaintext);
}


/*
*	Validates the executed vector against the known-answer provided by CAVP.
*	Returns 2 on FAILURE and 3 on SUCCESS
*/
int validateAESVector(struct Vector *vector, struct Vector *answer) {
	int return_value	= 2;		// Fail by default.
	char *error	= alloca(256);
	bzero(error, 256);
	char *tmp_conv	= alloca(256);
	bzero(tmp_conv, 256);

	if (vector->content != NULL) {
		AESVector *test_vect	= (AESVector*) vector->content;
		if (answer != NULL) {
			AESVector *ans_vect	= (AESVector*) answer->content;
			if (test_vect->count == ans_vect->count) {
				if (test_vect->key_len == ans_vect->key_len) {
					if (test_vect->iv_len == ans_vect->iv_len) {
						if (cmpBinString(test_vect->iv, ans_vect->iv, ans_vect->iv_len)) {
							if (cmpBinString(test_vect->key, ans_vect->key, ans_vect->key_len)) {
								if (test_vect->block_mode == AES_CFB1_BLOCK) {
									if (test_vect->plaintext_len == ans_vect->plaintext_len) {
										if (test_vect->ciphertext_len == ans_vect->ciphertext_len) {
											if (compareBitFields(test_vect->ciphertext, ans_vect->ciphertext, ans_vect->ciphertext_len)) {
												if (compareBitFields(test_vect->plaintext, ans_vect->plaintext, ans_vect->plaintext_len)) {
													return_value	= 3;
												}
												else sprintf(error, "Plaintext bitfield doesn't match. Expected (%s)\n", printBitFieldToBuffer(ans_vect->plaintext, ans_vect->plaintext_len, tmp_conv));
											}
											else sprintf(error, "Ciphertext bitfield doesn't match. Expected (%s)\n", printBitFieldToBuffer(ans_vect->ciphertext, ans_vect->ciphertext_len, tmp_conv));
										}
										else sprintf(error, "Ciphertext length is different. Expected (%zu) and found (%d).\n", strlen(ans_vect->ciphertext), test_vect->ciphertext_len);
									}
									else sprintf(error, "Plaintext length is different. Expected (%zu) and found (%d).\n", strlen(ans_vect->plaintext), test_vect->plaintext_len);
								}
								else{
									if (test_vect->plaintext_len == ans_vect->plaintext_len) {
										if (test_vect->ciphertext_len == ans_vect->ciphertext_len) {
											if (cmpBinString(test_vect->ciphertext, ans_vect->ciphertext, ans_vect->ciphertext_len)) {
												if (cmpBinString(test_vect->plaintext, ans_vect->plaintext, ans_vect->plaintext_len)) {
													return_value	= 3;
												}
												else sprintf(error, "Test (%s) plaintext doesn't match.\n", printBinStringToBuffer(ans_vect->plaintext, ans_vect->plaintext_len, tmp_conv));
											}
											else sprintf(error, "Test (%s) ciphertext doesn't match.\n", printBinStringToBuffer(ans_vect->ciphertext, ans_vect->ciphertext_len, tmp_conv));
										}
										else sprintf(error, "Ciphertext length is different. Expected (%d) and found (%d).\n", ans_vect->ciphertext_len, test_vect->ciphertext_len);
									}
									else sprintf(error, "Plaintext length is different. Expected (%d) and found (%d).\n", ans_vect->plaintext_len, test_vect->plaintext_len);
								}
							}
							else sprintf(error, "Key doesn't match. Expected (%s)\n", printBinStringToBuffer(ans_vect->key, ans_vect->key_len, tmp_conv));
						}
						else sprintf(error, "IV doesn't match. Expected (%s)\n", printBinStringToBuffer(ans_vect->iv, ans_vect->iv_len, tmp_conv));
					}
					else sprintf(error, "IV length is different.\n");
				}
				else sprintf(error, "Key length is different.\n");
			}
			else sprintf(error, "COUNT parameter doesn't match. Expected (%d)\n", ans_vect->count);
		}
		else sprintf(error, "Test (%s) doesn't have an answer key.\n", vector->name);
	}
	else sprintf(error, "Test (%s) doesn't have a vector.\n", vector->name);
	vector->execd	= return_value;
	if (strlen(error) > 0) vector->err	= strdup(error);
	return return_value;
}


/*
*	Function writes response files for CAVP.
*/
void dumpAESVector(struct Vector *vector, FILE *fp) {
	AESVector *t_vect	= (AESVector*) vector->content;
	if (vector->flags != NULL) {
		int		out_len	= totalStrLen(vector->flags);
		char*	output	= alloca(out_len);
		bzero(output, out_len);
		collapseIntoBuffer(vector->flags, output);
		fprintf(fp, "%s", output);
		fprintf(fp, "\n\n");
	}

	fprintf(fp, "COUNT = %d\n", t_vect->count);

	if (t_vect->key_len > 0) {
		fprintf(fp, "KEY = ");
		printBinStringToFile(t_vect->key, t_vect->key_len, fp);
		fprintf(fp, "\n");
	}

	if (t_vect->iv_len > 0) {
		fprintf(fp, "IV = ");
		printBinStringToFile(t_vect->iv, t_vect->iv_len, fp);
		fprintf(fp, "\n");
	}

	if (!t_vect->oper) {
		if (t_vect->plaintext_len > 0) {
			fprintf(fp, "PLAINTEXT = ");
			if (t_vect->block_mode == AES_CFB1_BLOCK) printBinStringAsBinToFile(t_vect->plaintext, t_vect->plaintext_len, fp);
			else printBinStringToFile(t_vect->plaintext, t_vect->plaintext_len, fp);
			fprintf(fp, "\n");
		}
	
		if (t_vect->ciphertext_len > 0) {
			fprintf(fp, "CIPHERTEXT = ");
			if (t_vect->block_mode == AES_CFB1_BLOCK) printBinStringAsBinToFile(t_vect->ciphertext, t_vect->ciphertext_len, fp);
			else printBinStringToFile(t_vect->ciphertext, t_vect->ciphertext_len, fp);
			fprintf(fp, "\n");
		}
	}
	else {
		if (t_vect->ciphertext_len > 0) {
			fprintf(fp, "CIPHERTEXT = ");
			if (t_vect->block_mode == AES_CFB1_BLOCK) printBinStringAsBinToFile(t_vect->ciphertext, t_vect->ciphertext_len, fp);
			else printBinStringToFile(t_vect->ciphertext, t_vect->ciphertext_len, fp);
			fprintf(fp, "\n");
		}

		if (t_vect->plaintext_len > 0) {
			fprintf(fp, "PLAINTEXT = ");
			if (t_vect->block_mode == AES_CFB1_BLOCK) printBinStringAsBinToFile(t_vect->plaintext, t_vect->plaintext_len, fp);
			else printBinStringToFile(t_vect->plaintext, t_vect->plaintext_len, fp);
			fprintf(fp, "\n");
		}
	}
	
	fprintf(fp, "\n");
}


/*
*	Function to dump an AESVector to stdout.
*/
void printAESVector(struct Vector *vector) {
	AESVector *t_vect	= (AESVector*) vector->content;

	printf("TEST:\t\t\t\t%s\n", vector->name);
	printStatusLine(vector->execd);

	if (vector->err != NULL) printf("ERROR:\t\t\t\t%s", vector->err);

	printf("COUNT:\t\t\t\t%d\n", t_vect->count);

	if (t_vect->oper) printf("OPERATION:\t\tENCRYPT\n");
	else  printf("OPERATION:\t\tDECRYPT\n");

	if (t_vect->key_len > 0) {
		printf("KEY:\t\t\t\t");
		printBinString(t_vect->key, t_vect->key_len);
		printf("\n");
	}

	if (t_vect->iv_len > 0) {
		printf("IV:\t\t\t\t");
		printBinString(t_vect->iv, t_vect->iv_len);
		printf("\n");
	}

	if (t_vect->plaintext_len > 0) {
		printf("PLAINTEXT:\t\t");
		if (t_vect->block_mode == AES_CFB1_BLOCK) {
			printf("(%d)  ", t_vect->plaintext_len);
			printBinStringAsBin(t_vect->plaintext, t_vect->plaintext_len);
		}
		else printBinString(t_vect->plaintext, t_vect->plaintext_len);
		printf("\n");
	}

	if (t_vect->ciphertext_len > 0) {
		printf("CIPHERTEXT:\t");
		if (t_vect->block_mode == AES_CFB1_BLOCK) {
			printf("(%d)  ", t_vect->ciphertext_len);                       
			printBinStringAsBin(t_vect->ciphertext, t_vect->ciphertext_len);
		}
		else printBinString(t_vect->ciphertext, t_vect->ciphertext_len);
		printf("\n");
	}
	
	switch (t_vect->block_mode) {
		case AES_CFB1_BLOCK:
			printf("BLOCK MODE:\tCFB-1\n");
			break;
		case AES_CFB128_BLOCK:
			printf("BLOCK MODE:\tCFB-128\n");
			break;
		case AES_CFB8_BLOCK:
			printf("BLOCK MODE:\tCFB-8\n");
			break;
		case AES_OFB_BLOCK:
			printf("BLOCK MODE:\tOFB\n");
			break;
		case AES_CBC_BLOCK:
			printf("BLOCK MODE:\tCBC\n");
			break;
		case AES_ECB_BLOCK:
			printf("BLOCK MODE:\tECB\n");
			break;
		default:
			printf("BLOCK MODE:\tUNKNOWN\n");
			break;
	}
	printf("\n");
}


int parseAESVectorLine(AESVector *item, char *line) {
	char *divider	= strchr(line, 0x3d);		// Find the KVP delimiter...
	if (divider == NULL) {
		return -1;
	}
	int key_len	= (divider - line);
	divider++;
	int val_len	= strlen(divider);

	char *key	= alloca(key_len+1);
	char *val	= alloca(val_len+1);
	bzero(key, key_len+1);
	bzero(val, val_len+1);
	memcpy(key, line, key_len);
	memcpy(val, divider, val_len);

	key = trim(key);
	val = trim(val);

	if (strcmp(key, "KEY") == 0) {
		item->key		= malloc((strlen(val)/2)+1);
		item->key_len	= parseStringIntoBytes(val, item->key);
	}
	else if (strcmp(key, "IV") == 0) {
		item->iv		= malloc((strlen(val)/2)+1);
		item->iv_len	= parseStringIntoBytes(val, item->iv);
	}
	else if (strcmp(key, "PLAINTEXT") == 0) {
		if (item->block_mode == AES_CFB1_BLOCK) {
			int byte_len	= (strlen(val)/8)+1;
			item->plaintext		= malloc(byte_len);
			bzero(item->plaintext, byte_len);
			item->plaintext_len	= bint2bin(val, item->plaintext);
		}
		else {
			item->plaintext		= malloc((strlen(val)/2)+1);
			item->plaintext_len	= parseStringIntoBytes(val, item->plaintext);
		}
	}
	else if (strcmp(key, "CIPHERTEXT") == 0) {
		if (item->block_mode == AES_CFB1_BLOCK) {
			int byte_len	= (strlen(val)/8)+1;
			if (byte_len == 0) printf("************ %d", byte_len);
			item->ciphertext		= malloc(byte_len);
			bzero(item->ciphertext, byte_len);
			item->ciphertext_len	= bint2bin(val, item->ciphertext);
		}
		else {
			item->ciphertext		= malloc((strlen(val)/2)+1);
			item->ciphertext_len	= parseStringIntoBytes(val, item->ciphertext);
		}
	}
	else if (strcmp(key, "COUNT") == 0) item->count	= atoi(val);
	else printf("Unrecognized line.\n");
	return 0;
}


int assign_cipher_algo(AESVector *buff, char *name) {
	if (choose_aes_block_algo(buff, name) != 0) {
		printf("Could not determine the block-chaining algorithm for test (%s). Failing it...\n", name);
		return -1;
	}
	
	if		(strcasestr(name, "128.req") != NULL)	buff->key_size	= 128;
	else if	(strcasestr(name, "192.req") != NULL)	buff->key_size	= 192;
	else if	(strcasestr(name, "256.req") != NULL)	buff->key_size	= 256;
	else {
		printf("Could not determine the key size for test (%s). Failing it...\n", name);
		return -1;
	}

	// Now we need to know the block-chaining algo. Once we know that, we can select a cryptographic mode.
	// No need for a default case. Careful about order!! We don't want to match "CFB128" when searching for "CFB1".
	switch (buff->key_size) {
		case 128:
			switch (buff->block_mode) {
				case AES_CBC_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_128_cbc();		break;
				case AES_ECB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_128_ecb();		break;
				case AES_OFB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_128_ofb();		break;
				case AES_CFB1_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_128_cfb1();	break;
				case AES_CFB8_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_128_cfb8();	break;
				case AES_CFB128_BLOCK:	buff->cipher_algo	= FIPS_evp_aes_128_cfb128();	break;
			}
			break;
		case 192:
			switch (buff->block_mode) {
				case AES_CBC_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_192_cbc();		break;
				case AES_ECB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_192_ecb();		break;
				case AES_OFB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_192_ofb();		break;
				case AES_CFB1_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_192_cfb1();	break;
				case AES_CFB8_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_192_cfb8();	break;
				case AES_CFB128_BLOCK:	buff->cipher_algo	= FIPS_evp_aes_192_cfb128();	break;
			}
			break;
		case 256:
			switch (buff->block_mode) {
				case AES_CBC_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_256_cbc();		break;
				case AES_ECB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_256_ecb();		break;
				case AES_OFB_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_256_ofb();		break;
				case AES_CFB1_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_256_cfb1();	break;
				case AES_CFB8_BLOCK:		buff->cipher_algo	= FIPS_evp_aes_256_cfb8();	break;
				case AES_CFB128_BLOCK:	buff->cipher_algo	= FIPS_evp_aes_256_cfb128();	break;
			}
			break;
	}

	if (buff->cipher_algo == NULL) {
		printf("Apparently, we were handed a NULL algorithm for test (%s). This will probably cause validation failures.\n", name);
		return -1;
	}
	return 0;
}


/*
*	Before we can run the test, we need to know some things about it...
*	In this case, key size and block-chaining algo...
*/
int choose_aes_block_algo(AESVector *buff, char* name) {
	// First, we need to know the key size. It will be one of {128, 192, 256}....
	//	The funky indexing for the haystack string is due to lexical overlap between the algo and the key size.
	if		(strcasestr(name, "CBC") != NULL) 	buff->block_mode	= AES_CBC_BLOCK;
	else if	(strcasestr(name, "ECB") != NULL)		buff->block_mode	= AES_ECB_BLOCK;
	else if	(strcasestr(name, "OFB") != NULL)		buff->block_mode	= AES_OFB_BLOCK;
	else if	(strcasestr(name, "CFB128") != NULL)	buff->block_mode	= AES_CFB128_BLOCK;
	else if	(strcasestr(name, "CFB8") != NULL)	buff->block_mode	= AES_CFB8_BLOCK;
	else if	(strcasestr(name, "CFB1") != NULL)	buff->block_mode	= AES_CFB1_BLOCK;
	else	 return -1;
	
	return 0;
}


/*
*	Before we can run the test, we need to know some things about it...
*	In this function, we examine the type of the test, and the sizes of the inputs
*		to correctly determine the receiving buffer's size, and allocate memory
*		appropriately.
*	Returns 1 on success and 0 on failure.
*/
int aes_alloc_receive_buff(struct Vector *vector) {
	AESVector *t_vect	= (AESVector*) vector->content;
	int return_value		= 0;
	int buffer_length	= 0;

	if (!t_vect->oper) {		// Decryption
		buffer_length	= max(t_vect->ciphertext_len, AES_BLOCK_SIZE) + 16;

		t_vect->plaintext		= malloc(buffer_length);
		t_vect->plaintext_len		= t_vect->ciphertext_len;
		if (t_vect->plaintext != NULL) {
			bzero(t_vect->plaintext, buffer_length);
			return_value		= 1;
		}
		else printf("Failed to allocate memory for test (%s) plaintext buffer.\n", vector->name);
	}
	else {					// Encryption
		buffer_length	= max(t_vect->plaintext_len, AES_BLOCK_SIZE) + 16;

		t_vect->ciphertext		= malloc(buffer_length);
		t_vect->ciphertext_len	= t_vect->plaintext_len;
		if (t_vect->ciphertext != NULL) {
			bzero(t_vect->ciphertext, buffer_length);
			return_value		= 1;
		}
		else printf("Failed to allocate memory for test (%s) ciphertext buffer.\n", vector->name);
	}
	return return_value;
}


/*
*	This is the entry-point for the actual AES routines.
*/
int PROC_AES(struct Vector *vector) {
	AESVector *t_vect	= (AESVector*) vector->content;
	if (aes_alloc_receive_buff(vector)) {
		if (strcasestr(vector->name, "MCT") != NULL)	return PROC_AES_MCT(vector);
		else											return PROC_AES_VANILLA(vector);
	}
	return -1;
}


/*	Initialize (de)/(en)cryption context using OpenSSL. Then do the operation.
*	Note that we need to do some intelligent guessing about things like block-chaining algo and key-size.
*		We may or may not be provided with an IV.
*/
int PROC_AES_VANILLA(struct Vector *vector) {
	int return_value	= -1;		// Fail by default.
	AESVector *t_vect	= (AESVector*) vector->content;

	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	int buffer_length	= 0;

	if (t_vect->block_mode == AES_CFB1_BLOCK) EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPH_FLAG_LENGTH_BITS);

	FIPS_cipherinit(&ctx, t_vect->cipher_algo, t_vect->key, t_vect->iv, t_vect->oper);
	if (t_vect->oper)	FIPS_cipher(&ctx, t_vect->ciphertext, t_vect->plaintext, t_vect->plaintext_len);
	else 				FIPS_cipher(&ctx, t_vect->plaintext, t_vect->ciphertext, t_vect->ciphertext_len);
	return_value	= 1;

	FIPS_cipher_ctx_cleanup(&ctx);
	return return_value;
}


/*
*	AES Monte Carlo mode...
*	Note: We are going to end up creating new vectors as this test is run.
*
*	Adaptions and improvements were made to code mostly copied from
*	https://github.com/Excito/openssl/blob/master/fips/aes/fips_aesavs.c
*	Thank you V-ONE Corporation.
*/
int PROC_AES_MCT(struct Vector *vector) {
	int return_value	= -1;		// Fail by default.
	AESVector *t_vect	= (AESVector*) vector->content;
	AESVector *nu_vect	= NULL;

	struct Vector *nu_vector		= NULL;
	struct Vector *ptr_vector		= vector;

	// We're going to need a whole mess of space....
	unsigned char	key[101][32];
	unsigned char	iv[101][AES_BLOCK_SIZE];
	unsigned char	ptext[1001][32];
	unsigned char	ctext[1001][32];
	unsigned char	ciphertext[64+4];

	bzero(key, 32 * 101);
	bzero(iv, AES_BLOCK_SIZE * 101);
	bzero(ptext, 1001 * 32);
	bzero(ctext, 1001 * 32);
	bzero(ciphertext, 64+4);

	int i	= 0;
	int j	= 0;
	int n	= 0;

	int key_bytes = t_vect->key_size / 8;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	memcpy(key[0], t_vect->key, t_vect->key_len);
	memcpy(iv[0], t_vect->iv, t_vect->iv_len);

	if (t_vect->oper)	memcpy(ptext[0], t_vect->plaintext, t_vect->plaintext_len);
	else					memcpy(ctext[0], t_vect->ciphertext, t_vect->ciphertext_len);

	for(i = 0; i < 100; ++i) {
		for(j = 0; j < 1000; ++j) {
			switch (t_vect->block_mode) {
				case AES_ECB_BLOCK:
					if (j == 0) FIPS_cipherinit(&ctx, t_vect->cipher_algo, key[i], iv[i], t_vect->oper);
					if (t_vect->oper) {
						FIPS_cipher(&ctx, ctext[j], ptext[j], t_vect->plaintext_len);
						memcpy(ptext[j+1], ctext[j], t_vect->plaintext_len);
					}
					else {
						FIPS_cipher(&ctx, ptext[j], ctext[j], t_vect->ciphertext_len);
						memcpy(ctext[j+1], ptext[j], t_vect->ciphertext_len);
					}
					break;
				case AES_CBC_BLOCK:
				case AES_OFB_BLOCK:
				case AES_CFB128_BLOCK:
					if (j == 0) {
						FIPS_cipherinit(&ctx, t_vect->cipher_algo, key[i], iv[i], t_vect->oper);
						if (t_vect->oper) {
							FIPS_cipher(&ctx, ctext[j], ptext[j], t_vect->plaintext_len);
							memcpy(ptext[j+1], iv[i], t_vect->plaintext_len);
						}
						else {
							FIPS_cipher(&ctx, ptext[j], ctext[j], t_vect->ciphertext_len);
							memcpy(ctext[j+1], iv[i], t_vect->ciphertext_len);
						}
					}
					else {
						if (t_vect->oper) {
							FIPS_cipher(&ctx, ctext[j], ptext[j], t_vect->plaintext_len);
							memcpy(ptext[j+1], ctext[j-1], t_vect->plaintext_len);
						}
						else {
							FIPS_cipher(&ctx, ptext[j], ctext[j], t_vect->ciphertext_len);
							memcpy(ctext[j+1], ptext[j-1], t_vect->ciphertext_len);
						}                                                                                                                                                 
					}
					break;                                                                  
				case AES_CFB8_BLOCK:
					if (j == 0) FIPS_cipherinit(&ctx, t_vect->cipher_algo, key[i], iv[i], t_vect->oper);

					if (t_vect->oper) {
						FIPS_cipher(&ctx, ctext[j], ptext[j], t_vect->plaintext_len);                
						if (j < 16)	memcpy(ptext[j+1], &iv[i][j], t_vect->plaintext_len);
						else			memcpy(ptext[j+1], ctext[j-16], t_vect->plaintext_len);
					}
					else	 {
						FIPS_cipher(&ctx, ptext[j], ctext[j], t_vect->ciphertext_len);
						if (j < 16)	memcpy(ctext[j+1], &iv[i][j], t_vect->ciphertext_len);
						else			memcpy(ctext[j+1], ptext[j-16], t_vect->ciphertext_len);
					}
					break;
				case AES_CFB1_BLOCK:
					if (j == 0) {
						FIPS_cipherinit(&ctx, t_vect->cipher_algo, key[i], iv[i], t_vect->oper);
						EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPH_FLAG_LENGTH_BITS);
					}

					if (t_vect->oper) {
						FIPS_cipher(&ctx, ctext[j], ptext[j], t_vect->plaintext_len);
						if (j < 128)	sb(ptext[j+1], 0, gb(iv[i], j));
						else			sb(ptext[j+1], 0, gb(ctext[j-128], 0));
					}
					else {
						FIPS_cipher(&ctx, ptext[j], ctext[j], t_vect->ciphertext_len);
						if (j < 128)	sb(ctext[j+1], 0, gb(iv[i], j));
						else			sb(ctext[j+1], 0, gb(ptext[j-128], 0));
					}
					break;
			}
		}
		--j;

		if (i != 0) {		// If this is not our initial vector...
			nu_vect			= INIT_VECTOR_AES(t_vect->oper);														// Create the new AESVector...
			nu_vect->count	= i;																								// ...save the relevant data...
			nu_vect->iv_len			= t_vect->iv_len;
			nu_vect->key_len			= t_vect->key_len;
			nu_vect->block_mode		= t_vect->block_mode;
			nu_vect->key_size		= t_vect->key_size;
			nu_vect->ciphertext_len	= t_vect->ciphertext_len;
			nu_vect->plaintext_len	= t_vect->plaintext_len;
			nu_vect->iv			= malloc(t_vect->iv_len);
			nu_vect->key			= malloc(t_vect->key_len);
			nu_vect->ciphertext	= malloc(t_vect->ciphertext_len);
			nu_vect->plaintext	= malloc(t_vect->plaintext_len);
			memcpy(nu_vect->iv, iv[i], nu_vect->iv_len);
			memcpy(nu_vect->key, key[i], nu_vect->key_len);

			nu_vector	= malloc(sizeof(struct Vector));		// ...create the container...
			nu_vector->content	= nu_vect;					// ...assign the vect to it...
			nu_vector->name		= strdup(vector->name);		// ...label it with the test name...
			nu_vector->execd		= -3;						// ...mark it as AWAITING VALIDATION...
			nu_vector->flags		= NULL;						// ...mark with no special flags...
			nu_vector->err		= NULL;						// ...and no error messages...
			
			if (!insertVectorAfterNode(nu_vector, ptr_vector)) printf("ERROR INSERTING new test vector for Test (%s).\n", vector->name);	// ...and append it to our list.
		}
		else {
			nu_vect		= t_vect;
			nu_vector	= vector;
		}

		if (t_vect->oper) {
			memcpy(nu_vect->ciphertext, ctext[j], nu_vect->ciphertext_len);
			memcpy(nu_vect->plaintext, ptext[0], nu_vect->plaintext_len);
		}
		else	 {
			memcpy(nu_vect->ciphertext, ctext[0], nu_vect->ciphertext_len);
			memcpy(nu_vect->plaintext, ptext[j], nu_vect->plaintext_len);
		}
		ptr_vector	= nu_vector;

		if (t_vect->oper) {
			if (t_vect->block_mode == AES_CFB8_BLOCK) for (n = 0; n < key_bytes; ++n) ciphertext[n] = ctext[(j-(key_bytes-1))+n][0];

			else if (t_vect->block_mode == AES_CFB1_BLOCK) for(n = 0; n < t_vect->key_size; ++n) sb(ciphertext, n, gb(ctext[(j-(t_vect->key_size-1))+n], 0));

			else {
				switch (t_vect->key_size) {
					case 128:
						memcpy(ciphertext, ctext[j], 16);
						break;
					case 192:
						memcpy(ciphertext, ctext[j-1]+8, 8);
						memcpy(ciphertext+8, ctext[j], 16);
						break;
					case 256:
						memcpy(ciphertext, ctext[j-1], 16);
						memcpy(ciphertext+16, ctext[j], 16);
						break;
				}
			}
		}
		else {
			if (t_vect->block_mode == AES_CFB8_BLOCK) 	for (n = 0; n < key_bytes; ++n) ciphertext[n] = ptext[(j-(key_bytes-1))+n][0];

			else if (t_vect->block_mode == AES_CFB1_BLOCK) for(n = 0; n < t_vect->key_size; ++n) sb(ciphertext, n, gb(ptext[(j-(t_vect->key_size-1))+n], 0));

			else {
				switch (t_vect->key_size) {
					case 128:
						memcpy(ciphertext, ptext[j], 16);
						break;
					case 192:
						memcpy(ciphertext, ptext[j-1]+8, 8);
						memcpy(ciphertext+8, ptext[j], 16);
						break;
					case 256:
						memcpy(ciphertext, ptext[j-1], 16);
						memcpy(ciphertext+16, ptext[j], 16);
						break;
				}
			}
		}
		for (n = 0; n < key_bytes; ++n) key[i+1][n] = key[i][n] ^ ciphertext[n];

		if (t_vect->oper) {
			switch (t_vect->block_mode) {
				case AES_ECB_BLOCK:
					memcpy(ptext[0], ctext[j], AES_BLOCK_SIZE);
					break;
				case AES_CBC_BLOCK:
				case AES_OFB_BLOCK:
				case AES_CFB128_BLOCK:
					memcpy(iv[i+1], ctext[j], AES_BLOCK_SIZE);
					memcpy(ptext[0], ctext[j-1], AES_BLOCK_SIZE);
					break;
				case AES_CFB8_BLOCK:
					for (n = 0; n < 16; ++n) iv[i+1][n] = ctext[(j-15)+n][0];
					ptext[0][0] = ctext[j-16][0];
					break;
				case AES_CFB1_BLOCK:
					for(n = 0; n < 128; ++n) sb(iv[i+1], n, gb(ctext[(j-127)+n], 0));
					ptext[0][0] = ctext[j-128][0] & 0x80;
					break;
			}
		}
		else {
			switch (t_vect->block_mode) {
				case AES_ECB_BLOCK:
					memcpy(ctext[0], ptext[j], AES_BLOCK_SIZE);
					break;
				case AES_CBC_BLOCK:
				case AES_OFB_BLOCK:
				case AES_CFB128_BLOCK:
					memcpy(iv[i+1], ptext[j], AES_BLOCK_SIZE);
					memcpy(ctext[0], ptext[j-1], AES_BLOCK_SIZE);
					break;
				case AES_CFB8_BLOCK:
					for (n = 0; n < 16; ++n) iv[i+1][n] = ptext[(j-15)+n][0];
					ctext[0][0] = ptext[j-16][0];
					break;
				case AES_CFB1_BLOCK:
					for(n = 0; n < 128; ++n) sb(iv[i+1], n, gb(ptext[(j-127)+n], 0));
					ctext[0][0] = ptext[j-128][0] & 0x80;
					break;
			}
		}
	}
	return_value	= 1;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return return_value;
}



/****************************************************************************************************
* Functions common to all types of tests.                                                           *
****************************************************************************************************/

/*
*	Given the Test, and a vector (the void pointer), traverse the list of extant vectors in the Test
*		and add this vector to the end of it.
*/
void addVectorToTest(struct Test *test, void *vector, struct StrLL *flag) {
	struct Vector *current		= test->vector_list;
	if (current == NULL) {
		test->vector_list	= malloc(sizeof(struct Vector));
		current		= test->vector_list;
		current->content	= vector;
		current->next	= NULL;
	}
	else {
		while (current->next != NULL) current = current->next;
		current->next	= malloc(sizeof(struct Vector));
		current	= current->next;
		current->content	= vector;
		current->next	= NULL;
	}
	
	current->flags	= flag;
	current->err		= NULL;
	current->execd	= 0;
	current->name	= strdup(test->name);
}


/*
*	Function interprets the given vector as an answer key to be added to the given test.
*		Marks vector as such, adds it to the test, and attaches the answer to the relevant
*		vector, if possible.
*/
void addAnswerKeyToTest(struct Test *test, void *new_ans_vect) {
	struct Vector *cur_ans		= test->answer_key;

	if (cur_ans == NULL) {
		test->answer_key	= malloc(sizeof(struct Vector));
		cur_ans	= test->answer_key;
	}
	else {
		while (cur_ans->next != NULL) cur_ans = cur_ans->next;
		cur_ans->next	= malloc(sizeof(struct Vector));
		cur_ans	= cur_ans->next;
	}
	cur_ans->flags	= NULL;		// No flags for answer keys.
	cur_ans->content	= new_ans_vect;
	cur_ans->err		= NULL;
	cur_ans->name	= NULL;
	cur_ans->next	= NULL;
	cur_ans->execd	= -2;	// Mark this vector as an answer key so it doesn't get run on accident.
	// TODO: Seek out the associated vector in the Test struct and bind to it.
}



/*
*	When we encounter a new test name, we ought to store some information about it. This will be used
*		later in the program when the user decides to write test results to files for submission to
*		CAVP. Function will check for duplicates and add the test data to the list if it isn't there
*		already. Returns void.
*/
struct Test* addTestToManifest(char* test, char* algo){
	struct Test *current	= root_node;
	struct Test *last		= NULL;
	int i = 0;
	int added = 0;
	char* temp_ptr;
	char* dup	= strdupa(test);		// Make a copy of the input so we don't ruin it.

	while ((current != NULL) && (added == 0)) {
		if (strcasestr(dup, current->name) != NULL) {		// Did we find ourselves in the list?
			added = 1;
		}
		else {
			last = current;
			current = current->next;
		}
	}

	// At this point, we have either reached the end of the list, or we found ourselves.
	if (added) return current;		// If we were already added, return.

	// If we did NOT find ourselves in the list, allocate a new Test.

		current	= malloc(sizeof(struct Test));			// Alloc new heap space for the new Test.
		if (last != NULL) last->next = current;
		temp_ptr	= strcasestr(dup, ".req");			// Strip the extension.
		if (temp_ptr != NULL) *temp_ptr	= '\0';		// Strip the extension.
		current->name			= strdup(dup);
		current->algo			= algo;
		current->vector_list		= NULL;
		current->answer_key		= NULL;
		current->next			= NULL;
		current->comment_list		= NULL;

		// Setup the proper function pointers.
		if (strcasecmp(algo, "ECDSA") == 0) {
			current->exec_fxn		= &PROC_ECDSA;
			current->dump_fxn		= &dumpECDSAVector;
			current->print_fxn		= &printECDSAVector;
			//current->parse_fxn		= &parseECDSAVectorLine;
			current->validate_fxn		= &validateECDSAVector;
			current->free_fxn		= &freeECDSAVector;
		}
		else if (strcasecmp(algo, "HMAC") == 0) {
			current->exec_fxn		= &PROC_HMAC;
			current->dump_fxn		= &dumpHMACVector;
			current->print_fxn		= &printHMACVector;
			//current->parse_fxn		= &parseHMACVectorLine;
			current->validate_fxn		= &validateHMACVector;
			current->free_fxn		= &freeHMACVector;
		}
		else if (strcasecmp(algo, "SHA") == 0) {
			current->exec_fxn		= &PROC_SHA;
			current->dump_fxn		= &dumpSHAVector;
			current->print_fxn		= &printSHAVector;
			//current->parse_fxn		= &parseSHAVectorLine;
			current->validate_fxn		= &validateSHAVector;
			current->free_fxn		= &freeSHAVector;
		}
		else if (strcasecmp(algo, "RNG") == 0) {
			current->exec_fxn		= &PROC_RNG;
			current->dump_fxn		= &dumpRNGVector;
			current->print_fxn		= &printRNGVector;
			//current->parse_fxn		= &parseRNGVectorLine;
			current->validate_fxn		= &validateRNGVector;
			current->free_fxn		= &freeRNGVector;
		}
		else if (strcasecmp(algo, "AES") == 0) {
			current->exec_fxn		= &PROC_AES;
			current->dump_fxn		= &dumpAESVector;
			current->print_fxn		= &printAESVector;
			//current->parse_fxn		= &parseAESVectorLine;
			current->validate_fxn		= &validateAESVector;
			current->free_fxn		= &freeAESVector;
		}
		else printf("Failed to find function-handler for the algo (%s).\n", algo);

	if (root_node == NULL) root_node = current;

	return current;
}


/*
*	Dump all vectors of a given Test to its proper file.
*/
void dumpTest(struct Test *test) {
	struct Vector* t_vect;
	FILE *file;
	if (test->vector_list != NULL) {
		if (test->dump_fxn != NULL) {
			file	= openResponseFile(test);
			if (file != NULL) {
				t_vect = test->vector_list;
				while (t_vect != NULL) {
					if (t_vect->execd >= 2) test->dump_fxn(t_vect, file);
					t_vect = t_vect->next;
				}
				fclose(file);
			}
		}
		else{
			printf("Uh oh... encountered a test algorithm (%s) that we don't know how to handle. Doing nothing...\n", test->algo);
		}
	}
	else{
		printf("The test (%s::%s) doesn't have any vectors attached to it. Doing nothing...\n", test->algo, test->name);
	}
}


/*
*	This is the root function call that will write all executed tests to files for submission to CAVP.
*	First clears away any prior files.
*/
void writeTestResults(struct StrLL *filter) {
	struct Test *current	= root_node;
	int i = 0;
	while (current != NULL) {
		if (filter == NULL) dumpTest(current);
		else if (is_str_loose_match(filter, current->algo)) dumpTest(current);
		else if (is_str_loose_match(filter, current->name)) dumpTest(current);
		current	= current->next;
	}
}


/*
*	Opens a file in write-mode. If the file already exists, its contents will be destroyed.
*	If the file did not exist, it will be created.
*	Writes the basic header info into the file before returning it's pointer.
*/
FILE* openResponseFile(struct Test *test) {
	FILE *file;
	char *this_test_file	= alloca(256);
	bzero(this_test_file, 256);
	strcat(this_test_file, test_root);
	strcat(this_test_file, "/");
	strcat(this_test_file, test->algo);
	strcat(this_test_file, "/resp/");
	strcat(this_test_file, test->name);
	strcat(this_test_file, ".resp");

	printf("Writing file (%s).\n", this_test_file);

	file = fopen(this_test_file, "w");
	if (file == NULL)	printf("Failed to open file () for writing.\n", this_test_file);
	else {			// Write header info.
		int comment_len	= totalStrLen(test->comment_list);
		if (comment_len > 0) {
			char *temp_comments	= alloca(comment_len);
			bzero(temp_comments, comment_len);
			collapseIntoBuffer(test->comment_list, temp_comments);
			fprintf(file, "%s\n", temp_comments);
		}

		time_t rawtime;
		time(&rawtime);
		fprintf(file, "# Generated on %s\n\n", asctime(localtime(&rawtime)));
	}
	return file;
}



/*
*	Execute all the tests that we presently have loaded. Returns the number of tests
*		that were executed, whether they succeeded or not.
*/
int execTests(struct StrLL *filter) {
	struct Test *current	= root_node;
	int i = 0;
	int e = 0;
	int pass = 0;
	int fail = 0;

	while (current != NULL) {
		if (current->exec_fxn != NULL) {
			struct Vector *cur_vect = current->vector_list;
			while (cur_vect != NULL) {
				if ((filter == NULL) || (is_str_loose_match(filter, current->name)) || is_str_loose_match(filter, current->algo)) {
					if (cur_vect->execd == 0) {
						cur_vect->execd = current->exec_fxn(cur_vect);
						if (cur_vect->execd == -1) fail++;
						else if (cur_vect->execd == 1) pass++;
						e++;
					}
					else if (cur_vect->execd != -3) {
						printf("Ignored vector (%s) because it had an exec code of %d.\n", current->name, cur_vect->execd);
						i++;
					}
				}
				cur_vect	= cur_vect->next;
			}
		}
		else printf("Unknown algorithm (%s). Skipping test (%s).\n", current->algo, current->name);
		current	= current->next;
	}
	if ((e == 0) && (i == 0)) printf("There are no tests loaded.\n");
	else printf("Ignored %d vectors and executed %d vectors. Of those vectors executed...\n\t %d vectors passed\n\t %d failed\n\t %d vectors had indeterminate results\n", i, e, pass, fail, (e-(pass+fail)));
	return e;
}


/*
*	Validates all the tests that we successfully executed against a loaded known-answer.
*		Returns the number of tests that were processed, whether they validated or not.
*/
int validateTests(struct StrLL *filter) {
	struct Test *current	= root_node;
	int i = 0;
	int v = 0;
	int pass = 0;
	int fail = 0;

	while (current != NULL) {
		if (current->validate_fxn != NULL) {
			struct Vector *cur_vect	= current->vector_list;
			struct Vector *cur_ans	= current->answer_key;
			while (cur_vect != NULL) {
				if ((filter == NULL) || (is_str_loose_match(filter, current->name)) || is_str_loose_match(filter, current->algo)) {
					if ((cur_vect->execd == 1) || (cur_vect->execd == -3)) {	// Only validate vectors that executed successfully.
						switch (current->validate_fxn(cur_vect, cur_ans)) {
							case 2:
								fail++;
								break;
							case 3:
								pass++;
								break;
						}
						v++;
					}
					else i++;
				}
				cur_vect	= cur_vect->next;
				if (cur_ans != NULL) cur_ans	= cur_ans->next;
			}
		}
		else printf("Validation function is not set for algorithm (%s). Skipping test (%s).\n", current->algo, current->name);
		current	= current->next;
	}
	if ((v == 0) && (i == 0)) printf("There are no tests loaded.\n");
	else printf("Ignored %d vectors and validated %d vectors. Of those vectors validated...\n\t %d vectors passed\n\t %d failed\n", i, v, pass, fail);
	return v;
}



/**
* Pass the Test that is to be removed and free'd.
*/
void unlink_test(struct Test *link) {
	struct Test *current	= root_node;
	struct Test *last	= NULL;
	struct Test *next	= NULL;
	
	while (current != NULL) {
		if (current == link) {
			if (last == NULL) root_node	= current->next;
			else last->next	= current->next;

			destroyStrLL(current->comment_list);

			if (current->free_fxn != NULL) {
				struct Vector *cur_vect = current->vector_list;
				struct Vector *lst_vect = NULL;
				while (cur_vect != NULL) {				// Free the test vectors under this Test. 
					destroyStrLL(cur_vect->flags);
					cur_vect->flags	= NULL;
					if (cur_vect->name != NULL)	free(cur_vect->name);
					if (cur_vect->err != NULL)	free(cur_vect->err);
					current->free_fxn(cur_vect);
					cur_vect->name	= NULL;
					cur_vect->err	= NULL;
					lst_vect	= cur_vect;
					cur_vect	= cur_vect->next;
					free(lst_vect->content);
					free(lst_vect);
				}
				cur_vect = current->answer_key;
				lst_vect = NULL;
				while (cur_vect != NULL) {				// Free the answer key for this Test.
					destroyStrLL(cur_vect->flags);
					cur_vect->flags	= NULL;
					if (cur_vect->name != NULL)	free(cur_vect->name);
					if (cur_vect->err != NULL)	free(cur_vect->err);
					current->free_fxn(cur_vect);
					cur_vect->name	= NULL;
					cur_vect->err	= NULL;
					lst_vect	= cur_vect;
					cur_vect	= cur_vect->next;
					free(lst_vect->content);
					free(lst_vect);
				}
			}
			else printf("Cannot free a vector because there is no free function defined for it.\n");

			if (current->name != NULL) free(current->name);
			next		= current->next;
			free(current);
			current	= next;
		}
		else {
			last		= current;
			current	= current->next;
		}
	}
}


/*
*	Unload the tests.
*/
int unloadTests(struct StrLL *filter) {
	int return_value	= 0;
	struct Test *current	= root_node;
	struct Test *link	= NULL;

	if (current != NULL) {
		while (current != NULL) {
			if ((filter == NULL) || (is_str_loose_match(filter, current->name)) || is_str_loose_match(filter, current->algo)) {
				struct Test *link	= current->next;
				printf("Unloading %s....\n", current->name);
				unlink_test(current);		// Drop the test.
				return_value++;
				current = link;
			}
			else current	= current->next;
		}
	}
	else printf("There are no tests loaded.\n");
	printf("Unloaded %d Tests.\n", return_value);
	return return_value;
}


/*
*	List all the tests that we have.
*/
int listTests(struct StrLL *filter) {
	struct Test *current	= root_node;
	int i = 0;

	if (current != NULL) {
		while (current != NULL) {
			if ((filter == NULL) || (is_str_loose_match(filter, current->name)) || is_str_loose_match(filter, current->algo)) listTest(current);
			current	= current->next;
		}
	}
	else printf("There are no tests loaded.\n");

	return i;
}


/*
*	Given a Test as an argument, print an overview.
*/
void listTest(struct Test *test) {
	struct Vector *cur_vect;
	int vectors		= 0;
	int answer_keys	= 0;
	int executed		= 0;
	int passed		= 0;
	int failed		= 0;
	int unexecuted	= 0;
	int unvalidated	= 0;
	int exec_failed	= 0;
	cur_vect = test->vector_list;
	while (cur_vect != NULL) {
		switch (cur_vect->execd) {
			case -1:	exec_failed++;	unvalidated++;		break;
			case 0:	unexecuted++;	unvalidated++;		break;
			case -3:	executed++;		unvalidated++;		break;
			case 1:	executed++;		unvalidated++;		break;
			case 2:	executed++;		failed++;			break;
			case 3:	executed++;		passed++;			break;
		}
		vectors++;
		cur_vect	= cur_vect->next;
	}
	// Count the answer keys...
	cur_vect	= test->answer_key;
	while (cur_vect != NULL) {
		answer_keys++;
		cur_vect	= cur_vect->next;
	}
	printf("%s (%s) containing %d vectors and %d answer keys.\n", test->name, test->algo, vectors, answer_keys);
	if (unexecuted > 0)	printf("\t%d vectors unexecuted\n", unexecuted);
	if (unvalidated > 0)	printf("\t%d vectors unvalidated\n", unvalidated);
	if (failed > 0)		printf("\t%d vectors failed validation\n", failed);
	if (passed > 0)		printf("\t%d vectors validated correctly\n", passed);
	printf("\n");
}



/*
*	Loads all of the tests and vectors for a given algo.
*	Returns the number of vectors loaded, or -1 on failure.
*/
int buildTestVectors(char *test) {
	struct Test		*current;
	void		*active_vect	= NULL;
	DIR *dir;
	struct dirent *ent;
	FILE *fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char *this_test_file	= alloca(256);
	bzero(this_test_file, 256);

	char *this_test_path	= alloca(128);
	bzero(this_test_path, 128);

	strcat(this_test_path, test_root);
	strcat(this_test_path, "/");
	strcat(this_test_path, test);
	strcat(this_test_path, "/req");

	int v_count	= 0;			// Keep a running count of how many vectors have been read in.

	// These are test-level params that may or may not be used for any given test, but
	//	if they ARE used, they will apply to every vector within the test. Sometimes this data
	//	is derivable from data within the vector alone, but since I'm not sure how picky CAVP
	//	will be about the format of the response files, we might end up using it later to rebuild
	//	the RESP file in exactly the same format as the REQ file.
	int				enc_dec		= 1;		// For AES-derived algos. 1->ENCRYPT, 0->DECRYPT
	unsigned char	*seed;					// For RNG and MC modes.
	char			*curve;					// ECDSA uses named curves.
	int				seed_len	= 0;		// Length of the seed array.
	int				L			= -1;		// The L parameter.
	struct StrLL*	write_flag	= NULL;			// If this is not NULL, it means we have a flag to write to the Vector.

	if ((dir = opendir(this_test_path)) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if ((strcmp(ent->d_name, ".") != 0) && (strcmp(ent->d_name, "..") != 0)) {
				bzero(this_test_file, 256);
				strcat(this_test_file, this_test_path);
				strcat(this_test_file, "/");
				strcat(this_test_file, ent->d_name);
				current	= NULL;
				write_flag	= NULL;

				fp = fopen(this_test_file, "r");
				if (fp != NULL) {
					current	= addTestToManifest(ent->d_name, test);		// Keep the name of the test handy for when we decide to write responses.
					seed_len	= 0;
					enc_dec		= 0;
					L			= -1;
					curve		= NULL;
					while ((read = getline_ind(&line, &len, fp)) != -1) {		// This loop constitutes the start of the parser.
						if (line[0] == '#') {								// Commentary. Store for later output.
							if (strcasestr(line, "Generated") == NULL) {		// Do not store the line containing the word 'Generated'.
								current->comment_list	= stackStrOntoList(current->comment_list, trim(line));
							}
						}
						else if (strlen(line) < 3) {						// Blank line. Attach the current vector to the current Test.
							if (active_vect != NULL) {
								v_count++;
								addVectorToTest(current, active_vect, write_flag);		// Add active_vect to current.
								write_flag	= NULL;
								active_vect	= NULL;
							}
						}
						else if (strcasecmp(test, "AES") == 0) {					// Cased-off parse...
							if (strcmp(trim(line), "[ENCRYPT]") == 0) {		// All tests that follow are ENCRYPT tests.
								write_flag	= stackStrOntoList(write_flag, trim(line));
								enc_dec = 1;
							}
							else if (strcmp(trim(line), "[DECRYPT]") == 0) {
								write_flag	= stackStrOntoList(write_flag, trim(line));
								enc_dec = 0;	
							}	// All tests that follow are DECRYPT tests.
							else {
								// If we are in this block, we don't have to special-case the line.
								// Make sure that we have a vector allocated.
								if (active_vect == NULL) {
									active_vect = INIT_VECTOR_AES(enc_dec);
									if (assign_cipher_algo(active_vect, ent->d_name) != 0) {		// Choose the block-chaining algo...
										printf("Failed to set parameters for AES test (%s). This will cause problems later on.\n", ent->d_name);
									}
								}
								parseAESVectorLine(active_vect, line);		// Parse the AES line.
							}
						}
						else if (strcasecmp(test, "SHA") == 0) {
							if (strcasestr(trim(line), "Seed") != NULL) {			// This test requires a seed parameter.
								// This is a bit weird... The Monte Carlo tests ONLY specify a seed...
								char* temp_ptr	= strcasestr(line, "=");
								seed	= alloca(strlen(strcasestr(line, "=")+2)/2);
								seed_len = parseStringIntoBytes((strcasestr(line, "=")+2), seed);
								active_vect = INIT_VECTOR_SHA(ent->d_name, L, seed, seed_len);
								seed_len	= 0;
								seed	= NULL;
							}
							else if (strcasestr(trim(line), "[L =") != NULL) {		// TODO: Hax. Make more robust.
								char* temp_ptr	= strcasestr(line, "]");
								write_flag	= stackStrOntoList(write_flag, trim(line));
								*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
								L	= atoi((strcasestr(line, "=")+1));
							}
							else {
								// If we are in this block, we don't have to special-case the line.
								// Make sure that we have a vector allocated.
								if (active_vect == NULL) active_vect = INIT_VECTOR_SHA(ent->d_name, L, seed, seed_len);
								parseSHAVectorLine(active_vect, line);		// Parse the SHA line.
							}
						}
						else if (strcasecmp(test, "RNG") == 0) {
							if ((strcmp(trim(line), "[X9.31]") == 0) || (strcasestr(line, "[AES ") != NULL)) {	
								write_flag	= stackStrOntoList(write_flag, trim(line));
							}
							else {
								// If we are in this block, we don't have to special-case the line.
								// Make sure that we have a vector allocated.
								if (active_vect == NULL) active_vect = INIT_VECTOR_RNG(ent->d_name, 0, NULL);
								parseRNGVectorLine(active_vect, line);		// Parse the RNG line.
							}
						}
						else if (strcasecmp(test, "HMAC") == 0) {
							if (strcasestr(trim(line), "[L=") != NULL) {		// TODO: Hax. Make more robust.
								char* temp_ptr	= strcasestr(line, "]");
								write_flag	= stackStrOntoList(write_flag, trim(line));
								*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
								L	= atoi((strcasestr(line, "=")+1));
							}
							else {
								// If we are in this block, we don't have to special-case the line.
								// Make sure that we have a vector allocated.
								if (active_vect == NULL) active_vect = INIT_VECTOR_HMAC(ent->d_name, L);
								parseHMACVectorLine(active_vect, line);		// Parse the HMAC line.
							}
						}
						else if (strcasecmp(test, "ECDSA") == 0) {
							if (strcasestr(trim(line), "[P-") != NULL) {		// One kind of curve.
								char* temp_ptr	= strcasestr(line, "]");
								write_flag	= stackStrOntoList(write_flag, trim(line));
								*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
								curve	= strdupa(trim(line)+1);
							}
							else if	(strcasestr(trim(line), "[K-") != NULL) {
								char* temp_ptr	= strcasestr(line, "]");
								write_flag	= stackStrOntoList(write_flag, trim(line));
								*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
								curve	= strdupa(trim(line)+1);
							}	// One kind of curve.
							else if	(strcasestr(trim(line), "[B-") != NULL) {
								char* temp_ptr	= strcasestr(line, "]");
								write_flag	= stackStrOntoList(write_flag, trim(line));
								*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
								curve	= strdupa(trim(line)+1);
							}	// One kind of curve.
							else {
								// If we are in this block, we don't have to special-case the line.
								// Make sure that we have a vector allocated.
								if (active_vect == NULL) active_vect = INIT_VECTOR_ECDSA(curve);
								parseECDSAVectorLine(active_vect, line);		// Parse the ECDSA line.
							}
						}
					}
					fclose(fp);

					// This block catches the condition of no tailing blank line. Ensures that no test is left behind because of it.
					if (active_vect != NULL) {
						addVectorToTest(current, active_vect, write_flag);
						active_vect	= NULL;
						write_flag	= NULL;
					}
				}
			}
		}
		closedir(dir);
		free(line);
	}
	else {
		printf("Failed to read the path %s\n", this_test_path);
	}
	printf("Loaded test block: %s  \t(%d vectors)\n", test, v_count);
	return v_count;
}



/*
*	Loads the answer-key for a given test.
*	This function must be called after buildTestVectors, as this assumes that all of the test
*		data is already loaded.
*/
int buildAnswerKey(struct Test *test) {
	void		*active_vect	= NULL;
	FILE *fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char *this_test_file	= alloca(256);
	bzero(this_test_file, 256);

	strcat(this_test_file, test_root);
	strcat(this_test_file, "/");
	strcat(this_test_file, test->algo);
	strcat(this_test_file, "/fax/");
	strcat(this_test_file, test->name);
	strcat(this_test_file, ".fax");

	int v_count	= 0;			// Keep a running count of how many vectors have been read in.

	// These are test-level params that may or may not be used for any given test, but
	//	if they ARE used, they will apply to every vector within the test. Sometimes this data
	//	is derivable from data within the vector alone, but since I'm not sure how picky CAVP
	//	will be about the format of the response files, we might end up using it later to rebuild
	//	the RESP file in exactly the same format as the REQ file.
	unsigned char	*seed;				// For RNG and MC modes.
	char				*curve;				// ECDSA uses named curves.
	int				seed_len	= 0;			// Length of the seed array.
	int				L			= -1;	// The L parameter.

	fp = fopen(this_test_file, "r");
	if (fp != NULL) {
		seed_len	= 0;
		L			= -1;
		curve		= NULL;
		while ((read = getline_ind(&line, &len, fp)) != -1) {		// This loop constitutes the start of the parser.
			if (line[0] == '#') {}							// Ignore commentary.
			else if (strlen(line) < 3) {						// Blank line. Attach the current vector to the current Test.
				if (active_vect != NULL) {
					v_count++;
					addAnswerKeyToTest(test, active_vect);		// Add active_vect to current.
					active_vect	= NULL;
				}
			}
			else if (strcasecmp(test->algo, "AES") == 0) {				// Cased-off parse...
				if (strcmp(trim(line), "[ENCRYPT]") == 0) {}		// Ignore. Answer-key is stateless.
				else if (strcmp(trim(line), "[DECRYPT]") == 0) {}	// Ignore. Answer-key is stateless.
				else {
					// If we are in this block, we don't have to special-case the line.
					// Make sure that we have a vector allocated.
					if (active_vect == NULL) {
						active_vect = INIT_VECTOR_AES(0);
						choose_aes_block_algo(active_vect, test->name);
					}
					parseAESVectorLine(active_vect, line);		// Parse the AES line.
				}
			}
			else if (strcasecmp(test->algo, "SHA") == 0) {
				if (strcasestr(trim(line), "Seed") != NULL) {			// This test requires a seed parameter.
					// This is a bit weird... The Monte Carlo tests ONLY specify a seed...
					char* temp_ptr	= strcasestr(line, "=");
					seed	= alloca(strlen(strcasestr(line, "=")+2)/2);
					seed_len = parseStringIntoBytes((strcasestr(line, "=")+2), seed);
				}
				else if (strcasestr(trim(line), "[L =") != NULL) {		// TODO: Hax. Make more robust.
					char* temp_ptr	= strcasestr(line, "]");
					*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
					L	= atoi((strcasestr(line, "=")+1));
				}
				else {
					// If we are in this block, we don't have to special-case the line.
					// Make sure that we have a vector allocated.
					if (active_vect == NULL) active_vect = INIT_VECTOR_SHA(test->name, L, seed, seed_len);
					parseSHAVectorLine(active_vect, line);		// Parse the SHA line.
				}
			}
			else if (strcasecmp(test->algo, "RNG") == 0) {
				if (strcmp(trim(line), "[X9.31]") == 0) {	}	// Not sure why this matters to us...
				else if (strcasestr(line, "[AES ") != NULL) {	}	// Ignore this too. We will derive it later.
				else {
					// If we are in this block, we don't have to special-case the line.
					// Make sure that we have a vector allocated.
					if (active_vect == NULL) active_vect = INIT_VECTOR_RNG(test->name, 0, NULL);
					parseRNGVectorLine(active_vect, line);		// Parse the RNG line.
				}
			}
			else if (strcasecmp(test->algo, "HMAC") == 0) {
				if (strcasestr(trim(line), "[L=") != NULL) {		// TODO: Hax. Make more robust.
					char* temp_ptr	= strcasestr(line, "]");
					*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
					L	= atoi((strcasestr(line, "=")+1));
				}
				else {
					// If we are in this block, we don't have to special-case the line.
					// Make sure that we have a vector allocated.
					if (active_vect == NULL) active_vect = INIT_VECTOR_HMAC(test->name, L);
					parseHMACVectorLine(active_vect, line);		// Parse the HMAC line.
				}
			}
			else if (strcasecmp(test->algo, "ECDSA") == 0) {
				if (strcasestr(trim(line), "[P-") != NULL) {		// One kind of curve.
					char* temp_ptr	= strcasestr(line, "]");
					*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
					curve	= strdupa(trim(line)+1);
				}
				else if	(strcasestr(trim(line), "[K-") != NULL) {
					char* temp_ptr	= strcasestr(line, "]");
					*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
					curve	= strdupa(trim(line)+1);
				}	// One kind of curve.
				else if	(strcasestr(trim(line), "[B-") != NULL) {
					char* temp_ptr	= strcasestr(line, "]");
					*temp_ptr	= '\0';		// Cut the line off at the angle bracket.
					curve	= strdupa(trim(line)+1);
				}	// One kind of curve.
				else {
					// If we are in this block, we don't have to special-case the line.
					// Make sure that we have a vector allocated.
					if (active_vect == NULL) active_vect = INIT_VECTOR_ECDSA(curve);
					parseECDSAVectorLine(active_vect, line);		// Parse the ECDSA line.
				}
			}
		}
		fclose(fp);
		free(line);

		// This block catches the condition of no tailing blank line. Ensures that no test is left behind because of it.
		if (active_vect != NULL) {
			addAnswerKeyToTest(test, active_vect);
			active_vect	= NULL;
		}
	}
	else {
		printf("Failed to read the answer key (%s)\n", this_test_file);
	}
	printf("Loaded %d answer keys for test %s.\n", v_count, test->name);
	return v_count;
}



/*
*	Loads the tests from the file system. Stores them into an array, ready to be run.
*	Returned the number of vectors that were loaded, or -1 on error.
*/
int parseTestsFromDir(struct StrLL *filter) {
	DIR *dir;
	struct dirent *ent;
	int blocks	= 0;
	int vectors	= 0;
	int	temp		= -1;

	dir = opendir(test_root);
	if (dir != NULL) {
		int i = 0;
		while ((ent = readdir(dir)) != NULL) {
			for (i = 0; i < (sizeof(enabled_tests)/sizeof(enabled_tests[0])); i++) {
				if (strcmp(ent->d_name, enabled_tests[i]) == 0) {
					if ((filter == NULL) || is_str_loose_match(filter, ent->d_name)) {
						temp		= buildTestVectors(enabled_tests[i]);
	
						if (temp >= 0) {
							blocks++;
							vectors	= vectors + temp;
						}
						else printf("There was a problem loading the test block %s.\n", ent->d_name);
						temp		= -1;
					}
				}
			}
		}
		closedir(dir);

		struct Test *test	= root_node;
		while (test != NULL) {
			buildAnswerKey(test);
			test	= test->next;
		}
	}
	else{
		printf("Failed to read a directory entry while parsing tests.\n");
		return -1;
	}
	printf("Loaded %d test blocks containing %d vectors.\n", blocks, vectors);
	return vectors;
}


/****************************************************************************************************
* Functions that just print things.                                                                 *
****************************************************************************************************/

/*
*	Given the name of a test, print all vectors in the test.
*/
void printTestByName(char *input) {
	struct Test *current	= root_node;
	struct Vector *cur_vect;
	while (current != NULL) {
		if (strcasestr(current->name, input)) {
			cur_vect = current->vector_list;
			while (cur_vect != NULL) {
				current->print_fxn(cur_vect);
				cur_vect	= cur_vect->next;
			}
		}
		current	= current->next;
	}
}


/*
*	Print the vectors that failed.
*/
void printFailedTests() {
	struct Test *current	= root_node;
	struct Vector *cur_vect;
	int err = 0;
	int ind = 0;
	int val = 0;
	while (current != NULL) {
		cur_vect = current->vector_list;
		while (cur_vect != NULL) {
			if ((cur_vect->execd == -1) || (cur_vect->execd == 2) || (cur_vect->execd == 0)) {
				listTest(current);
				break;
			}
			cur_vect	= cur_vect->next;
		}
		current	= current->next;
	}
	//printf("There were %d execution errors, %d failed validations and %d indeterminate results.\n", err, val, ind);
}


/*
*	An output function that prints the given number of integer values of a given binary string.
*	Overloaded to print to a file rather than stdout.
*/
void printBinStringToFile(unsigned char * str, int len, FILE *fp) {
	int i = 0;
	unsigned int moo	= 0;
	if ((str != NULL) && (len > 0)) {
		for (i = 0; i < len; i++) {
			moo	= *(str + i);
			fprintf(fp, "%02x", moo);
		}
	}
}


/*
*	An output function that prints the given number of integer values of a given binary string.
*/
void printBinString(unsigned char * str, int len) {
	int i = 0;
	unsigned int moo	= 0;
	if ((str != NULL) && (len > 0)) {
		for (i = 0; i < len; i++) {
			moo	= *(str + i);
			printf("%02x", moo);
		}
	}
}


/*
*	An output function that prints the given number of integer values of a given binary string.
*	Overloaded to print to a file rather than stdout.
*/
void printBinStringAsBinToFile(unsigned char *str, int len, FILE *fp) {
	int i = 0;
	if ((str != NULL) && (len > 0)) {
		for (i = 0; i < len; i++) {
			if (*(str + (i/8)) & (0x80 >> i)) fprintf(fp, "1");
			else fprintf(fp, "0");
		}
	}
}


/*
*	An output function that prints the given number of integer values of a given binary string.
*/
void printBinStringAsBin(unsigned char *str, int len) {
	int i = 0;
	if ((str != NULL) && (len > 0)) {
		for (i = 0; i < len; i++) {
			if (*(str + (i/8)) & (0x80 >> i)) printf("1");
			else printf("0");
		}
	}
}


/*
*	Given a status code, prints a nice colorful, human-readable status.
*/
void printStatusLine(int code) {
	switch (code) {
		case 0:		printf("STATUS:\t\t%c[36mNOT YET RUN%c[39m\n", 0x1B, 0x1B);			break;
		case 3:		printf("STATUS:\t\t%c[32mPASSED%c[39m\n", 0x1B, 0x1B);				break;
		case 2:		printf("STATUS:\t\t%c[31mFAILED VALIDATION%c[39m\n", 0x1B, 0x1B);	break;
		case 1:		printf("STATUS:\t\t%c[33mEXECUTED%c[39m\n", 0x1B, 0x1B);			break;
		case -1:		printf("STATUS:\t\t%c[31mFAILED EXECUTION%c[39m\n", 0x1B, 0x1B);	break;
		case -2:		printf("STATUS:\t\t%c[34mDO NOT EXECUTE%c[39m\n", 0x1B, 0x1B);		break;
		case -3:		printf("STATUS:\t\t%c[33mAWAITING VALIDATION%c[39m\n", 0x1B, 0x1B);	break;
		default:		printf("STATUS:\t\t%c[34mUNKNOWN%c[39m\n", 0x1B, 0x1B);			break;
	}
}


/*
*	PrObLeM???
*/
void troll() {
	printf("\n");
	printf("777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777\n");
	printf("777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777\n");
	printf("777777777777777777777777777777777............................................7777777777777777777777\n");
	printf("7777777777777777777777777................7777777777777777777777777777777777.....7777777777777777777\n");
	printf("7777777777777777777...........7777777777.....777777777777777..7777777777777777...777777777777777777\n");
	printf("77777777777777777....77777777777777777777777777777777777777777777..7777777777777...7777777777777777\n");
	printf("77777777777777....7777.77......777777777777...77777777777777..777777.777777777777...777777777777777\n");
	printf("777777777777....7777777777777777777777777777777777777777777777777..7777.7777777777...77777777777777\n");
	printf("77777777777...777777777777.....77777777777777777777.7777777777...777.7777.777777777...7777777777777\n");
	printf("7777777777..77777777777.7777777777777777777777777.7777777777777777..777.7777.7777777...777777777777\n");
	printf("7777777777..777777777.777777777777.7777777777777777777777777777777777.77.7777.7777777..777777777777\n");
	printf("7777777777..77777777.77777777777777777777777777777777777777777777777777.77.77777777777..77777777777\n");
	printf("777777777..777777777777777777777777777777777777777777..............7777777777777777777...7777777777\n");
	printf("77777777...777777777777........7777777777777777777.....777............77777777777777777...777777777\n");
	printf("7777....77777777777..............7777777777777....777777........77...777777777777777777...777777777\n");
	printf("777...777.....7...7...............77777777777...77777.................7777.7777........7....7777777\n");
	printf("77..777.777777777777777777.............7777777.........77777777777..777.777777777777777777...777777\n");
	printf("7..77.777..777777777777777777777....77777777777.....777777...77777777777777..........7777777..77777\n");
	printf("7..7.77.777......7777777777777777..7777777777777777777777777....7777777......777777....7777.7..7777\n");
	printf("7...77777..........7777.777777777..777777777777777777777777777...........77777..77777...777.77...77\n");
	printf("7...77777.7777777........77777777..7777777777777777777777777777777777777777777..777777..777.77...77\n");
	printf("7...77.7777777..77....77777777....77777777777777777777777777777777777777777.....7777777..77.777..77\n");
	printf("7..7777.777777..77777777777....7777777777777777........7777777777777777.....777......77..77.777..77\n");
	printf("7....777..77....7777777777.....77777777777777777777..77777777777777......77777...7...7...77.77...77\n");
	printf("77..7..77777....7777777..77.....777777777.......777..7777777777.......77777777..777777..777777...77\n");
	printf("77...7777.77..7...777.77777777...77777777777777.7...777777........7..7777777....77777..777.77...777\n");
	printf("777...77777.........777777777777......777777777777777........777777..7777......777777777..77..77777\n");
	printf("7777...7777..7..7......77777777777...77777777777........7777777777...7........7777777.77777...77777\n");
	printf("77777..7777....77..77........77777777..............77..7777777777.......77...7777777777.....7777777\n");
	printf("77777..7777....77..7777....................7777777777..777777........7777...777777777777...77777777\n");
	printf("77777..7777....77..777...7777777..7777777..7777777777...7.........7..777...77777777777...7777777777\n");
	printf("77777..7777........777..77777777..7777777..777777777...........7777..77...77777777777...77777777777\n");
	printf("77777..7777.................................................7777777......777777777777..777777777777\n");
	printf("77777..7777...........................................7..77777777777...7777777777777...777777777777\n");
	printf("77777..77777....................................7777777..777777777...77777777777777...7777777777777\n");
	printf("77777..77777..7...........................7..7777777777...77777....777777777777777...77777777777777\n");
	printf("77777..777777..7..77..777..77777...77777777..77777777777..777....777777777777777...7777777777777777\n");
	printf("77777..777777......7...777..77777..77777777..777777777777......7777777777777777...77777777777777777\n");
	printf("77777..7777777....777...77...7777..77777777..777777777......7777777.77777.777...7777777777777777777\n");
	printf("77777..777777777.........77..7777...7777777..77.........77777777.77777..777....77777777777777777777\n");
	printf("77777..77777777777777...............................777777777..7777..7777....7777777777777777777777\n");
	printf("7777...77777777.777777777777777777777777777777777777777777.77777..7777.....777777777777777777777777\n");
	printf("7777..7777777777.777777777777777777777777777777777777..777777.77777.....777777777777777777777777777\n");
	printf("7777..777777777777.777777777777777777777777777777..777777..77777.....777777777777777777777777777777\n");
	printf("77..77777..77777777...77777777777..........777777..7777777......77777777777777777777777777777777777\n");
	printf("7..777777777.7777777777777777777777777...777777777777.....77777777777777777777777777777777777777777\n");
	printf("7...7777777777...............777777777777777777777.....77777777777777777777777777777777777777777777\n");
	printf("7...777777777777777777777777777777777777777777.....777777777777777777777777777777777777777777777777\n");
	printf("77...77777777777777777777777777777777777..7.....777777777777777777777777777777777777777777777777777\n");
	printf("777....7777777777777777777777777777..........777777777777777777777777777777777777777777777777777777\n");
	printf("7777.....7777777777777777777.........77777777777777777777777777777777777777777777777777777777777777\n");
	printf("7777777........................77777777777777777777777777777777777777777777777777777777777777777777\n");
	printf("777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777\n");
	printf("\n\n");
}


/*
*	Prints a list of valid commands.
*/
void printHelp() {
	printf("==< HELP >=========================================================================================\n");
	printf("Ian's OpenSSL Workbench (v0.1.3)          Build date:  %s %s\n", __DATE__, __TIME__);
	printf("This program was designed to run CAVP 14.2 test vectors. It may work with other CAVP versions.\n");
	printf("The output of this program should NOT be construed as an indication of FIPS compliance.\n");
	printf("This program was written around OpenSSL v1.0.1d and FIPS Canister v2.0. But it should work with \n");
	printf("other recent versions.\n");
	printf("\n");
	printf("Type the name of a test to dump the test results.\n");
	printf("Type the name of a block to dump all tests within that block.\n");
	printf("\n");
	printf("'help'\t\t\t\tThis.\n");
	printf("'path <arg>'\tSet the path to the test vectors. Use if you didn't supply the path at launch.\n");
	printf("'run'\t\t\t\tEquivalent to 'load exec validate errors'.\n");
	printf("'load'\t\t\t\tLoads all supported tests from the filesystem.\n");
	printf("'list'\t\t\t\tLists all loaded tests.\n");
	printf("'exec'\t\t\t\tExecutes all loaded tests.\n");
	printf("'errors'\t\t\tList all tests that experienced problems or irregularities.\n");
	printf("'validate'\t\tValidate all tests against their repsective answer keys.\n");
	printf("'write'\t\t\t\tWrite all test data to output files suitable for CAVP reply.\n");
	printf("'unload'\t\t\tUnload all vectors for tests matching the given pattern.\n");
	printf("'quit'\t\t\t\tBail? Bail.\n");
	printf("\n");
	printf("The commands {list, run, exec, validate, write, load, unload} accept an optional unbounded list\n");
	printf("of arguments for Tests on which the command ought to be run.\n");
	printf("For example, 'load sha aes' would load only the SHA and AES test blocks.\n");
	printf("\n");
	printf("Typical usage sees the following sequence of commands: {load, exec, validate, write, quit}.\n");
	printf("\n\n");
}


/****************************************************************************************************
* Support functions for user input.                                                                 *
****************************************************************************************************/
/**
*	Takes string and breaks it up into a space-delimited chain of link-list items, which is returned. 
*/
struct StrLL* tokenize_user_input(char* input) {
	struct StrLL *return_value	= NULL;
	char *temp_str	= strtok(input, " ");
	if (temp_str != NULL) {
		while (temp_str != NULL) {
			return_value	= stackStrOntoList(return_value, temp_str);
			temp_str	= strtok(NULL, " ");
		}
	}
	else return_value	= stackStrOntoList(return_value, "");
	return return_value;
}



/****************************************************************************************************
* The main function.                                                                                *
****************************************************************************************************/

/**
*	Takes one additional parameter at runtime that is not required: The path of the test vectors.
*/
int main(int argc, char *argv[]) {
	int running	= 1;
	
	printf("\n");
	printf("===================================================================================================\n");
	printf("|                                      CAVP Test Apparatus                                        |\n");
	printf("===================================================================================================\n");

	ERR_load_crypto_strings();

	// Enter FIPS mode.
	if (FIPS_mode_set(1)) printf("FIPS mode was successfully enabled.\n");
	else {
		printf("Tried to enter FIPS mode, but lit ourselves on fire instead. Exiting...\n");
		unsigned long err_code	= ERR_get_error();
		printf("Library that generated the error:\t%s\n", ERR_lib_error_string(err_code));
		printf("Function that generated the error:\t%s\n", ERR_func_error_string(err_code));
		printf("Reason that generated the error:\t%s\n", ERR_reason_error_string(err_code));
		return -1;
	}

	OpenSSL_add_all_algorithms();
	printf("There are %d test-blocks enabled...   ", (int)(sizeof(enabled_tests)/sizeof(enabled_tests[0])));
	int i;
	for (i = (int)(sizeof(enabled_tests)/sizeof(enabled_tests[0]))-1; i >= 0; i--) printf("%s ", enabled_tests[i]);
	printf("\n");
	
	if (argv[1] != NULL) test_root = argv[1];
	printf("We expect to find the test vectors in %s.\n", test_root);

	char *input_text	= alloca(U_INPUT_BUFF_SIZE);	// Buffer to hold user-input.
	char *trimmed, *t_iterator;					// Temporary pointers for manipulating user-input.
	struct StrLL* parsed	= NULL;

	// The main loop. Run forever.
	while (running) {
		printf("%c[36m%s> %c[39m", 0x1B, argv[0], 0x1B);
		bzero(input_text, U_INPUT_BUFF_SIZE);
		if (fgets(input_text, U_INPUT_BUFF_SIZE, stdin) != NULL) {
			trimmed	= strchr(input_text, '\n');
			if (trimmed != NULL) *trimmed = '\0';						// Eliminate a possible newline character.
			trimmed	= trim(input_text);								// Nuke any excess whitespace the user might have entered.
			//t_iterator	= trimmed;
			//while(*t_iterator++ = toupper(*t_iterator));				// Convert to uniform case...
			parsed	= tokenize_user_input(trimmed);

			// Begin the cases...
			if (strlen(parsed->str) == 0) 				printHelp();						// User entered nothing.
			else if (strcasestr(parsed->str, "QUIT"))		running = 0;						// Exit
			else if (strcasestr(parsed->str, "HELP"))		printHelp();						// Show help.
			else if (strcasestr(parsed->str, "LIST"))		listTests(parsed->next);			// List the loaded tests.
			else if (strcasestr(parsed->str, "EXEC"))		execTests(parsed->next);			// Run all the things.
			else if (strcasestr(parsed->str, "UNLOAD"))	unloadTests(parsed->next);		// Unload tests.
			else if (strcasestr(parsed->str, "LOAD"))		parseTestsFromDir(parsed->next);	// Load all the tests from filesystem.
			else if (strcasestr(parsed->str, "TROLL"))		troll();							// prOBleM?.
			else if (strcasestr(parsed->str, "VALIDATE"))	validateTests(parsed->next);		// Write the output to the appropriate files.
			else if (strcasestr(parsed->str, "PATH")) {									// Specify the path to the vector definitions and answer keys.
				if (parsed->next == NULL) printf("We expect to find the test vectors in %s.\n", test_root);
				else {
					//destroyStrLL(parsed);		// Need to re-do this because paths are cased.
					//parsed	= tokenize_user_input(trimmed);
					test_root = strdupa(parsed->next->str);
					printf("We now expect to find the test vectors in %s.\n", test_root);
				}
			}
			else if (strcasestr(parsed->str, "WRITE"))		writeTestResults(parsed->next);	// Write the output to the appropriate files.
			else if (strcasestr(parsed->str, "ERRORS"))	printFailedTests();				// P	rint a list of problems to the screen.
			else if (strcasestr(parsed->str, "RUN")) {										// Print a list of problems to the screen.
				parseTestsFromDir(parsed->next);
				execTests(parsed->next);
				validateTests(parsed->next);
				printFailedTests();
			}
			else {													// Any other input, we will assume the user is looking to dump a particular test.
				printTestByName(trimmed);
			}
			destroyStrLL(parsed);
		}
		else {
			printHelp();
		}
	}
	unloadTests(NULL);
	return 0;
}
