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

void 	usage(t_ssl *ssl)
{
	ft_printf("%s: illegal option -- -\nusage: %s [-qr] [-s string] [files ...]\n", ssl->name, ssl->name);
	exit(1);
}

void	print_results(t_ssl *ssl, unsigned char *str, int len)
{
	int	i;

	i = 0;
	if (ssl->flags.quiet == 0 && ssl->flags.reverse == 0 && ssl->input_type == FILE)
		ft_printf("%s (%s) = ", ssl->name, ssl->input_name);
	else if (ssl->flags.quiet == 0 && ssl->flags.reverse == 0 && ssl->input_type == STRING)
		ft_printf("%s (\"%s\") = ", ssl->name, ssl->input_name);
	while (i < len)
		ft_printf("%.2x", str[i++]);
	if (ssl->flags.quiet == 0 && ssl->flags.reverse == 1 && ssl->input_type == FILE)
		ft_printf(" %s", ssl->input_name);
	else if (ssl->flags.quiet == 0 && ssl->flags.reverse == 1 && ssl->input_type == STRING)
		ft_printf(" \"%s\"", ssl->input_name);
	free(ssl->text);
	ft_printf("\n");
	ssl = 0;
}

char	*process_string(t_ssl *ssl, char **argv, int *i)
{
	char	*str;

	if (argv[*i][2])
		str = argv[*i] + 2;
	else
	{
		*i += 1;
		str = argv[*i];
	}
	if (str == 0)
		usage(ssl);
	ssl->message_len = ssl_strlen(str);
	ssl->input_type = STRING;
	ssl->input_name = str;
	return (str);
}

char	*process_file(t_ssl *ssl, char *file_name)
{
	t_read	rd;
	char	*file_content;
	char	*temp;
	int		i;
	int		start;

	start = 1;
	if (file_name == NULL)
		rd.fd = 0;
	else if ((rd.fd = open(file_name, O_RDONLY, 0)) < 0)
	{
		ft_printf("Failed to open file\n");
		exit(1);
	}
	rd.length = 0;
	while ((rd.buffer_chars = read(rd.fd, rd.buffer, BUFFER_SIZE)))
	{
		if (start)
		{
			start = 0;
			file_content = (char *)malloc(sizeof(char) * (rd.buffer_chars + 1));
			i = 0;
			while (i < rd.buffer_chars)
			{
				file_content[i] = rd.buffer[i];
				i++;
			}
			rd.length = rd.buffer_chars;
		}
		else
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
	}
	close(rd.fd);
	ssl->message_len = rd.length;
	ssl->input_type = FILE;
	ssl->input_name = file_name;
	return (file_content);
}