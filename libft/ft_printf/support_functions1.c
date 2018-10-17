/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   support_functions.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/15 09:11:28 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/09/15 09:11:29 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	ft_write(char c, t_fmt *fmt)
{
	ft_putchar(c);
	fmt->printed_current++;
	fmt->printed++;
}

void	print_sign(t_fmt *fmt)
{
	if (fmt->negative == 0 && fmt->plus == 1)
		ft_write('+', fmt);
	if (fmt->negative == 1)
		ft_write('-', fmt);
}

void	print_buf(char buf[64], t_fmt *fmt, int len)
{
	int	i;
	int precision;

	if (fmt->null == 1 && fmt->precision == 0)
		return ;
	i = 0;
	precision = fmt->precision - len;
	while (i < precision)
	{
		ft_write('0', fmt);
		i++;
	}
	i = 0;
	while (i < len)
	{
		ft_write(buf[64 - len + i], fmt);
		i++;
	}
}

void	apply_postfix(t_fmt *fmt)
{
	int i;
	int filler_length;

	i = 0;
	filler_length = fmt->width - fmt->printed_current;
	if (fmt->minus)
	{
		while (i < filler_length)
		{
			ft_write(' ', fmt);
			i++;
		}
	}
}

int		ft_utoa_base(uintmax_t n, int base, char buf[64])
{
	int			i;
	static char char_base[] = "0123456789abcdef";

	i = 0;
	if (n == 0)
	{
		buf[64 - i - 1] = '0';
		return (1);
	}
	while (n)
	{
		buf[64 - i - 1] = char_base[n % base];
		n = n / base;
		i++;
	}
	return (i);
}
