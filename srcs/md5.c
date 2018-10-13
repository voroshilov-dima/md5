#include "ft_ssl.h"

static void init_context(t_md5 *context)
{
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	context->a = 0;
	context->b = 0;
	context->c = 0;
	context->d = 0;
	context->reverse = 0;
	context->quiet = 0;
}

static void	append_padding(t_md5 *context, char *str)
{
	uint64_t	i;
	uint64_t	message_len;
	uint64_t	message_len_in_bits;

	message_len = md_strlen(str);
	if (message_len % 64 < 56)
		context->final_len = (message_len / 64 + 1) * 64;
	else
		context->final_len = (message_len / 64 + 2) * 64;
	context->text = (unsigned char *)malloc(sizeof(char) * context->final_len);
	ft_memcpy(context->text, str, message_len);
	context->text[message_len] = 128;
	i = message_len + 1;
	while (i < context->final_len - 8)
	{
		context->text[i] = 0;
		i++;
	}
	message_len_in_bits = message_len * 8;
	while (i < context->final_len)
	{
		context->text[i] = (message_len_in_bits >> 8 * (context->final_len - i)) & 0b11111111;
		i++;
	}
}

static void	process_string(t_md5 *context, char *str)
{
	int				i;
	unsigned char	buf[64];

	append_padding(context, str);
	ft_memcpy(buf, context->text, 64);
	md5_transform(context, buf);
	words_to_chars(buf, context->state, 16);
	i = 0;
	while (i < 16)
		printf("%.2x", buf[i++]);
	printf("\n");
	printf("quiet: %d\n", context->quiet);
	printf("reverse: %d\n", context->reverse);
}

void		md5(int argc, char **argv)
{
	t_md5	context;
	int	i;

	init_context(&context);
	i = 2;
	while (i < argc)
	{
		if (ft_strcmp(argv[i], "-r") == 0)
			context.reverse = 1;
		else if (ft_strcmp(argv[i], "-q") == 0)
			context.quiet = 1;
		else if (argv[i][0] == '-' && argv[i][1] == 's')
			process_string(&context, argv[i] + 2);
		else if (argv[i][0] == '-')
			printf("%s\n", "md5: illegal option -- -\nusage: md5 [-qr] [-s string] [files ...]");
		else
			printf("process file\n");
 	    i++;
	}
}
