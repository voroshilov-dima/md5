#include "ft_ssl.h"

void 	init_context(t_md5 *context)
{
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	context->a = 0;
	context->b = 0;
	context->c = 0;
	context->d = 0;
}

static void	process_string(t_md5 *context, char *str)
{
	int				i;
	int				len;
	unsigned char	buf[64];

	len = ft_strlen(str);
	ft_memcpy(buf, str, len);
	buf[len] = 128;
	i = len + 1;
	while (i < 56)
	{
		buf[i] = 0;
		i++;
	}
	buf[56] = 40;
	i++;
	while (i < 64)
	{
		buf[i] = 0;
		i++;
	}
	i = 0;
	transform(context, buf);
	words_to_chars(buf, context->state, 16);
	i = 0;
	while (i < 16)
		printf("%.2x", buf[i++]);
	printf("\n");
}

void		md5(int argc, char **argv)
{
	t_md5	context;
	int	i;

	init_context(&context);
	i = 2;
	while (i < argc)
	{
		if (argv[i][0] == '-' && argv[i][1] == 's')
 	    	process_string(&context, argv[i] + 2);
 	    i++;
	}
}
