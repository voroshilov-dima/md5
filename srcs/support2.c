#include "ft_ssl.h"

void		append_padding(t_ssl *ssl, char *str)
{
	uint64_t	i;
	
	if (ssl->message_len % 64 < 56)
		ssl->final_len = (ssl->message_len / 64 + 1) * 64;
	else
		ssl->final_len = (ssl->message_len / 64 + 2) * 64;
	ssl->text = (unsigned char *)malloc(sizeof(char) * ssl->final_len);
	ft_memcpy(ssl->text, str, ssl->message_len);
	ssl->text[ssl->message_len] = 128;
	i = ssl->message_len + 1;
	while (i < ssl->final_len - 8)
	{
		ssl->text[i] = 0;
		i++;
	}
}

void 	usage(char *str)
{
	if (ft_strcmp(str, "md5"))
		printf("%s\n", "md5: illegal option -- -\nusage: md5 [-qr] [-s string] [files ...]");
	else if (ft_strcmp(str, "sha256"))
		printf("%s\n", "sha256: illegal option -- -\nusage: md256 [-qr] [-s string] [files ...]");
	exit(1);
}

void	print_results(t_ssl *ssl, unsigned char *str, int len)
{
	int	i;

	i = 0;
	while (i < len)
		printf("%.2x", str[i++]);
	printf("\n");
	printf("quiet: %d\n", ssl->flags.quiet);
	printf("reverse: %d\n", ssl->flags.reverse);
}

char		*store_file(t_ssl *ssl, char *file_name)
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
	ssl->message_len = rd.length;
	return (file_content);
}