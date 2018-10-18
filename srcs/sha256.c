#include "ft_ssl.h"

static void init_sha256(t_ssl *ssl)
{
	ssl->name = "sha256";
	ssl->sha256.state[0] = 0x6a09e667;
	ssl->sha256.state[1] = 0xbb67ae85;
	ssl->sha256.state[2] = 0x3c6ef372;
	ssl->sha256.state[3] = 0xa54ff53a;
	ssl->sha256.state[4] = 0x510e527f;
	ssl->sha256.state[5] = 0x9b05688c;
	ssl->sha256.state[6] = 0x1f83d9ab;
	ssl->sha256.state[7] = 0x5be0cd19;
	ssl->sha256.a = 0;
	ssl->sha256.b = 0;
	ssl->sha256.c = 0;
	ssl->sha256.d = 0;
	ssl->sha256.e = 0;
	ssl->sha256.f = 0;
	ssl->sha256.g = 0;
	ssl->sha256.h = 0;
}

static void	append_length(t_ssl *ssl)
{
	uint64_t	i;
	uint64_t	message_len_in_bits;
	
	message_len_in_bits = ssl->message_len * 8;
	i = ssl->final_len - 8;
	while (i < ssl->final_len)
	{
		ssl->text[i] = (message_len_in_bits >> 8 * (ssl->final_len - i - 1)) & 0b11111111;
		i++;
	}
}

static void processing(t_ssl *ssl, char *str)
{
	uint64_t		i;
	unsigned char	digest[32];
	unsigned char	buf[64];

	init_sha256(ssl);
	append_padding(ssl, str);
	append_length(ssl);
	i = 0;
	while (i * 64 < ssl->final_len)
	{
		ft_memcpy(buf, ssl->text + i * 64, 64);
		sha256_transform(&ssl->sha256, buf);
		i++;
	}
	i = 0;
	words_to_chars(digest, ssl->sha256.state, 32, 0);
	print_results(ssl, digest, 32);
}

void		sha256(int argc, char **argv)
{
	t_ssl	ssl;
	int		i;

	init_ssl(&ssl);
	init_sha256(&ssl);
	i = 2;
	while (i < argc)
	{
		if (ft_strcmp(argv[i], "-r") == 0)
			ssl.flags.reverse = 1;
		else if (ft_strcmp(argv[i], "-q") == 0)
			ssl.flags.quiet = 1;
		else if (ft_strcmp(argv[i], "-p") == 0)
			processing(&ssl, process_file(&ssl, NULL));
		else if (argv[i][0] == '-' && argv[i][1] == 's')
			processing(&ssl, process_string(&ssl, argv, &i));
		else if (argv[i][0] == '-')
			usage(&ssl);
		else
			processing(&ssl, process_file(&ssl, argv[i]));
		i++;
	}
	exit(0);
}