#include "ft_ssl.h"

void	chars_to_words(unsigned int *output, unsigned char *input, unsigned int len)
{
	unsigned int	i;
	unsigned int	j;

	i = 0;
	j = 0;

	while (j < len)
	{
		output[i] = ((unsigned int)input[j])				| 
					(((unsigned int)input[j + 1]) << 8)		|
					(((unsigned int)input[j + 2]) << 16)	|
					(((unsigned int)input[j + 3]) << 24);
		j += 4;
		i++;
	}
}

void	words_to_chars(unsigned char *output, unsigned int *input, unsigned int len)
{
	unsigned int	i;
	unsigned int	j;

	i = 0;
	j = 0;
	while (j < len)
	{
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff); 	
		j += 4;
		i++;
	}
}

void	md_memset(unsigned char *output, int value, unsigned int len)
{
	unsigned int	i;

	i = 0;
	while (i < len)
	{
		((char *)output)[i] = (char)value;
		i++;		
	}
}

uint64_t	md_strlen(const char *s)
{
	uint64_t	i;

	i = 0;
	while (*s++ != '\0')
		i++;
	return (i);
}
