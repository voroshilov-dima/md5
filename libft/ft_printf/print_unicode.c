/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_unicode.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/06 15:45:12 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/10/06 15:45:14 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void		print_unicode_buf(t_fmt *fmt, char buf[4], int len)
{
	int	i;

	i = 0;
	while (i < len)
	{
		ft_write(buf[i], fmt);
		i++;
	}
}

int			unicode_char_len(wchar_t c)
{
	int	len;

	if (c < 128)
		len = 1;
	else if (c < 2048)
		len = 2;
	else if (c < 65536)
		len = 3;
	else
		len = 4;
	return (len);
}

int			print_unicode_char(t_fmt *fmt, wchar_t c)
{
	char	buf[4];
	int		len;
	int		i;

	len = unicode_char_len(c);
	i = len - 1;
	while (i >= 1)
		buf[i--] = mask_and_shift(&c);
	if (len == 1)
		buf[0] = c;
	else if (len == 2)
		buf[0] = (c & 0b11111) | 0b11000000;
	else if (len == 3)
		buf[0] = (c & 0b11111) | 0b11100000;
	else
		buf[0] = (c & 0b11111) | 0b11110000;
	print_unicode_buf(fmt, buf, len);
	return (len);
}

int			ft_strlen_unicode(t_fmt *fmt, wchar_t *s)
{
	int	len;
	int i;
	int temp;

	len = 0;
	i = 0;
	while (s[i] != '\0')
	{
		temp = unicode_char_len(s[i]);
		if (fmt->precision == -1 || fmt->precision >= len + temp)
			len += temp;
		else
			break ;
		i++;
	}
	return (len);
}

void		print_unicode_string(t_fmt *fmt, wchar_t *str)
{
	int				filler_length;
	int				i;
	static wchar_t	nul[6] = L"(null)";

	if (str == NULL)
		str = nul;
	filler_length = fmt->width - ft_strlen_unicode(fmt, str);
	if (filler_length && fmt->minus == 0)
		print_filler(fmt, filler_length);
	i = 0;
	while (*str && (fmt->precision == -1
		|| i + unicode_char_len(*str) <= fmt->precision))
	{
		i += print_unicode_char(fmt, *str);
		str++;
	}
	if (filler_length && fmt->minus)
		apply_postfix(fmt);
}
