/* Контекст MD5. */
typedef struct {
  UINT4 state[4];           /* состояние (ABCD) */
  UINT4 count[2];           /* число битов, modulo 2^64 (сначала младший) */
  unsigned char buffer[64]; /* входной буфер*/
} MD5_CTX;

void MD5Init PROTO_LIST ((MD5_CTX *));
void MD5Update PROTO_LIST ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));