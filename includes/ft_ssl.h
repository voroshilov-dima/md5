#ifndef FT_SSL_H
# define FT_SSL_H

# include "libft.h"
# include <stdio.h>
# include <fcntl.h>

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

# define BUFFER_SIZE 100

typedef struct		s_read
{
	int		fd;
	char	buffer[BUFFER_SIZE];
	int		buffer_chars;
	int		length;
}					t_read;

typedef struct 		s_flags
{
	int				quiet;
	int				reverse;
}					t_flags;

typedef struct		s_md5 {
	uint32_t		state[4];
	uint32_t		x[16];
	uint32_t		a;
	uint32_t		b;
	uint32_t		c;
	uint32_t		d;
} 					t_md5;

typedef struct		s_sha256 {
	uint32_t		state[8];
	uint32_t		x[64];
	uint32_t		a;
	uint32_t		b;
	uint32_t		c;
	uint32_t		d;
	uint32_t		e;
	uint32_t		f;
	uint32_t		g;
	uint32_t		h;
} 					t_sha256;

typedef struct		s_ssl
{
	unsigned char	*text;
	uint64_t		message_len;
	uint64_t		final_len;
	t_flags			flags;
	t_sha256		sha256;
	t_md5			md5;
}					t_ssl;

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTATE_RIGHT(x,2) ^ ROTATE_RIGHT(x,13) ^ ROTATE_RIGHT(x,22))
#define EP1(x) (ROTATE_RIGHT(x,6) ^ ROTATE_RIGHT(x,11) ^ ROTATE_RIGHT(x,25))
#define SIG0(x) (ROTATE_RIGHT(x,7) ^ ROTATE_RIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTATE_RIGHT(x,17) ^ ROTATE_RIGHT(x,19) ^ ((x) >> 10))

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

void		md5(int argc, char **argv);
void		sha256(int argc, char **argv);
void		init_ssl(t_ssl *ssl);
void		usage(char *str);
void		append_padding(t_ssl *ssl, char *str);
char		*store_file(t_ssl *ssl, char *file_name);
void		print_results(t_ssl *ssl, unsigned char *str, int len);
void		chars_to_words(unsigned int *output, unsigned char *input, unsigned int len);
void		words_to_chars(unsigned char *output, unsigned int *input, unsigned int len, int inverse);
void		ssl_memset(unsigned char *output, int value, unsigned int len);
void		md5_transform(t_md5 *md5, unsigned char block[64]);
void		sha256_transform(t_sha256 *sha256, unsigned char block[64]);
uint64_t	ssl_strlen(const char *s);

#endif