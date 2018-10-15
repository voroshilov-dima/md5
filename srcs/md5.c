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
	uint64_t	message_len_in_bits;

	if (context->message_len % 64 < 56)
		context->final_len = (context->message_len / 64 + 1) * 64;
	else
		context->final_len = (context->message_len / 64 + 2) * 64;
	context->text = (unsigned char *)malloc(sizeof(char) * context->final_len);
	ft_memcpy(context->text, str, context->message_len);
	context->text[context->message_len] = 128;
	i = context->message_len + 1;
	while (i < context->final_len - 8)
	{
		context->text[i] = 0;
		i++;
	}
	message_len_in_bits = context->message_len * 8;
	while (i < context->final_len)
	{
		context->text[i] = (message_len_in_bits >> 8 * i) & 0b11111111;
		i++;
	}
}

static void	print_results(t_md5 *context, unsigned char *str, int len) // make general for all
{
	int	i;

	i = 0;
	while (i < len)
		printf("%.2x", str[i++]);
	printf("\n");
	printf("quiet: %d\n", context->quiet);
	printf("reverse: %d\n", context->reverse);
}

static void processing(t_md5 *context, char *str)
{
	uint64_t		i;
	unsigned char	buf[64];

	append_padding(context, str);
	i = 0;
	while (i * 64 < context->final_len)
	{
		ft_memcpy(buf, context->text + i * 64, 64);
		md5_transform(context, buf);
		i++;
	}
	words_to_chars(buf, context->state, 16);
	print_results(context, buf, 16);
}

static void	process_file(t_md5 *context, char *file_name)
{
	t_read	rd;
	char	*file_content;
	char	*temp;
	int		i;

	if ((rd.fd = open(file_name, O_RDONLY, 0)) < 0)
	{
		printf("Failed to open file\n");
		exit(1);
	}
	rd.length = 0;
	while ((rd.buffer_chars = read(rd.fd, rd.buffer, BUFFER_SIZE)))
	{
		if (file_content)
		{
			temp = (char *)malloc(sizeof(char) * (rd.length + rd.buffer_chars + 1));
			i = 0;
			while (i < rd.length)
			{
				temp[i] = file_content[i];
				i++;
			}
			i = 0;
			while (i < rd.buffer_chars)
			{
				temp[rd.length + i] = rd.buffer[i];
				i++;
			}
			temp[rd.length + rd.buffer_chars] = 0;
			free(file_content);
			file_content = temp;
			rd.length += rd.buffer_chars;
		}
		else
		{
			file_content = (char *)malloc(sizeof(char) * (rd.buffer_chars + 1));
			i = 0;
			while (i < rd.buffer_chars)
			{
				file_content[i] = rd.buffer[i];
				i++;
			}
			rd.length = rd.buffer_chars;
		}
	}
	close(rd.fd);
	context->message_len = rd.length;
	processing(context, file_content);
}

static void usage(void)
{
	printf("%s\n", "md5: illegal option -- -\nusage: md5 [-qr] [-s string] [files ...]");
	exit(1);
}

static void	process_string(t_md5 *context, char *str)
{
	if (str == 0)
		usage();
	context->message_len = md_strlen(str);
	processing(context, str);
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
		{
			if (argv[i][2])
				process_string(&context, argv[i] + 2);
			else
				process_string(&context, argv[++i]);
		}
		else if (argv[i][0] == '-')
			usage();
		else
			process_file(&context, argv[i]);
 	    i++;
	}
	exit(0);
}
