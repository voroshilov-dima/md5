#include "ft_ssl.h"

void MD5Init(MD5_CTX *context)
{
  context->count[0] = 0;
  context->count[1] = 0;
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

void MD5_memcpy(unsigned char *output, unsigned char *input, unsigned int len)
{
	unsigned int	i;

	i = 0;
	while (i < len)
	{
		output[i] = input[i];
		i++;
	}
}

void MD5_memset(unsigned char *output, int value, unsigned int len)
{
	unsigned int	i;

	i = 0;
	while (i < len)
	{
		((char *)output)[i] = (char)value;
		i++;		
	}
}

unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void Encode(unsigned char *output, unsigned long *input, unsigned int len)
{
	unsigned int i;
	unsigned int j;

	i = 0;
	j = 0;
	while (j < len)
	{
		output[j] = (unsigned char)(input[i] & 0xff);
 		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);		
 		i++;
 		j += 4;
	}
}

void Decode(unsigned long *output, unsigned char *input, unsigned int len)
{
	unsigned int	i;
	unsigned int	j;

	i = 0;
	j = 0;

	while (j < len)
	{
		output[i] = ((unsigned long)input[j]) | (((unsigned long)input[j+1]) << 8)
		| (((unsigned long)input[j+2]) << 16) | (((unsigned long)input[j+3]) << 24);
		j += 4;
		i++;
	}
}

/* F, G, H и I являются базовыми функциями MD5.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT циклически смещает x влево на n битов. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) {							\
	(a) += F ((b), (c), (d)) + (x) + (unsigned long)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define GG(a, b, c, d, x, s, ac) {							\
	(a) += G ((b), (c), (d)) + (x) + (unsigned long)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define HH(a, b, c, d, x, s, ac) { 							\
	(a) += H ((b), (c), (d)) + (x) + (unsigned long)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define II(a, b, c, d, x, s, ac) { 							\
	(a) += I ((b), (c), (d)) + (x) + (unsigned long)(ac);	\
	(a) = ROTATE_LEFT ((a), (s)); 							\
	(a) += (b); 											\
}

void MD5Print(unsigned char digest[16])
{
	unsigned int	i;

	i = 0;
	while (i < 16)
	{
		printf("%02x", digest[i]);
		i++;
	}
}

void MD5Transform(unsigned long state[4], unsigned char block[64])
{
	unsigned long a;
	unsigned long b;
	unsigned long c;
	unsigned long d;
	unsigned long x[16];

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	Decode (x, block, 64);

	/* Круг 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Круг 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Круг 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Круг 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Обнуление чувствительных данных. */
	MD5_memset((unsigned char *)x, 0, sizeof (x));
}

void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
	unsigned int	i;
	unsigned int	index;
	unsigned int	partLen;

	/* Расчет числа байтов mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);
	
	/* Обновление числа битов */
	if ((context->count[0] += ((unsigned long)inputLen << 3)) < ((unsigned long)inputLen << 3))
 		context->count[1]++;
  	context->count[1] += ((unsigned long)inputLen >> 29);

	partLen = 64 - index;
	printf("1\n");
	/* Преобразование возможное число раз. */
	if (inputLen >= partLen)
	{
		
		MD5_memcpy((unsigned char *)&context->buffer[index], (unsigned char *)input, partLen);
 		MD5Transform(context->state, context->buffer);
 		i = 0;
 		while (i + 63 < inputLen)
 		{
 			MD5Transform(context->state, &input[i]);
 			i++;		
 		}
 		index = 0;
 	}
	else
		i = 0;

	/* Буферизация оставшихся входных данных */
  	MD5_memcpy((unsigned char *)&context->buffer[index], (unsigned char *)&input[i], inputLen-i);
}

void MD5Final(unsigned char digest[16], MD5_CTX *context)
{
  unsigned char	bits[8];
  unsigned int	index;
  unsigned int	padLen;

  /* Сохранение числа битов */
  Encode (bits, context->count, 8);

  /* Заполнение до 56 mod 64. */
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update(context, PADDING, padLen);

  /* Добавление размера (до заполнения) */
  MD5Update(context, bits, 8);

  /* Сохранение состояния в дайджесте */
  Encode(digest, context->state, 16);

  /* Обнуление чувствительной информации. */
  MD5_memset((unsigned char *)context, 0, sizeof (*context));
}

void MD5String(char *string)
{
	MD5_CTX context;
	unsigned char	digest[16];
	unsigned int	len;

	len = ft_strlen(string);
	MD5Init(&context);
	MD5Update(&context, (unsigned char *)string, len);
	MD5Final(digest, &context);

	//printf ("MD%d (\"%s\") = ", MD, string);
	MD5Print(digest);
	printf("\n");
}

void MD5File(char *filename)
{
	FILE *file;
	// MD_CTX context;
	// int len;
	// unsigned char buffer[1024];
	// unsigned char digest[16];

	if ((file = fopen(filename, "r")) == NULL)
 		printf ("%s can't be opened\n", filename);
	else {
	 // 	MDInit (&context);
	 // 	while ((len = fread(buffer, 1, 1024, file)))
	 //  		MDUpdate (&context, buffer, len);
	 // 	MDFinal (digest, &context);
		// fclose (file);
	 // 	MDPrint (digest);
 		printf ("\n");
  	}
}

int	main(int argc, char **argv)
{
	int	i;

	i = 1;
	while (i < argc)
	{
		if (argv[i][0] == '-' && argv[i][1] == 's')
     		MD5String(argv[i] + 2);
   		// else if (strcmp (argv[i], "-t") == 0)
     // 		MDTimeTrial ();
   		// else if (strcmp (argv[i], "-x") == 0)
     // 		MDTestSuite ();
   		else
     		MD5File(argv[i]);
     	i++;
	}
	
	return (0);
}