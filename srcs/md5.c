#include "ft_ssl.h"

static void init_md5(t_md5 *md5)
{
	md5->state[0] = 0x67452301;
	md5->state[1] = 0xefcdab89;
	md5->state[2] = 0x98badcfe;
	md5->state[3] = 0x10325476;
	md5->a = 0;
	md5->b = 0;
	md5->c = 0;
	md5->d = 0;
}

static void	append_length(t_ssl *ssl)
{
	uint64_t	i;
	uint64_t	message_len_in_bits;
	
	message_len_in_bits = ssl->message_len * 8;
	i = ssl->final_len - 8;
	while (i < ssl->final_len)
	{
		ssl->text[i] = (message_len_in_bits >> 8 * i) & 0b11111111;
		i++;
	}
}

static void processing(t_ssl *ssl, char *str)
{
	uint64_t		i;
	unsigned char	digest[16];
	unsigned char	buf[64];

	init_md5(&ssl->md5);
	append_padding(ssl, str);
	append_length(ssl);
	i = 0;
	while (i * 64 < ssl->final_len)
	{
		ft_memcpy(buf, ssl->text + i * 64, 64);
		md5_transform(&ssl->md5, buf);
		i++;
	}
	words_to_chars(digest, ssl->md5.state, 16, 1);
	print_results(ssl, digest, 16);
}

void		md5(int argc, char **argv)
{
	t_ssl	ssl;
	int		i;

	init_ssl(&ssl);
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
