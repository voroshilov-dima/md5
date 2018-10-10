#ifndef FT_SSL_H
# define FT_SSL_H

# include <stdio.h>
# include "libft.h"

# define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
# define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
# define H(x, y, z) ((x) ^ (y) ^ (z))
# define I(x, y, z) ((y) ^ ((x) | (~z)))

# define S11 7
# define S12 12
# define S13 17
# define S14 22
# define S21 5
# define S22 9
# define S23 14
# define S24 20
# define S31 4
# define S32 11
# define S33 16
# define S34 23
# define S41 6
# define S42 10
# define S43 15
# define S44 21

typedef struct		s_md5 {
	unsigned int	state[4];
	unsigned int	x[16];
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
} 					t_md5;

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) {							\
	(a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define GG(a, b, c, d, x, s, ac) {							\
	(a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define HH(a, b, c, d, x, s, ac) { 							\
	(a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));							\
	(a) += (b);												\
}
#define II(a, b, c, d, x, s, ac) { 							\
	(a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac);	\
	(a) = ROTATE_LEFT ((a), (s)); 							\
	(a) += (b); 											\
}

void	md5(int argc, char **argv);
void	chars_to_words(unsigned int *output, unsigned char *input, unsigned int len);
void	words_to_chars(unsigned char *output, unsigned int *input, unsigned int len);
void	md_memset(unsigned char *output, int value, unsigned int len);
void	transform(t_md5 *md, unsigned char block[64]);

#endif