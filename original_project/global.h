#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER определяет базовый тип указателя */
typedef unsigned char *POINTER;

/* UINT2 определяет 2-байтовое слово */
typedef unsigned short int UINT2;

/* UINT4 определяет 4-байтовое слово */
typedef unsigned long int UINT4;

/* PROTO_LIST определяется в зависимости от определенного ранее значения PROTOTYPES.
   При использовании PROTOTYPES список PROTO_LIST будет возвращать прототипы,
   иначе будет пустым.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif