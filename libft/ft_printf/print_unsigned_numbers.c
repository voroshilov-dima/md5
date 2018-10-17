/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_unsigned_numbers.c                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/15 09:11:24 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/09/15 09:11:25 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

static int			calculate_filler_length(t_fmt *fmt, int len)
{
	int i;

	i = fmt->width - len;
	if (fmt->null == 1 && fmt->precision == 0)
		i++;
	if (fmt->hash == 1)
	{
		if (fmt->type == 'o' || fmt->type == 'O')
			i -= 1;
		else if (fmt->type == 'x' || fmt->type == 'X' || fmt->type == 'p')
			i -= 2;
	}
	if (fmt->precision != -1 && (fmt->precision - len > 0))
		i -= fmt->precision - len;
	if (i < 0)
		i = 0;
	return (i);
}

static void			apply_prefix(t_fmt *fmt, int len)
{
	int		i;
	int		filler_length;

	i = 0;
	filler_length = calculate_filler_length(fmt, len);
	if (fmt->filler == '0')
		apply_hash(fmt);
	if (fmt->minus == 0)
		while (i < filler_length)
		{
			ft_write(fmt->filler, fmt);
			i++;
		}
	if (fmt->filler == ' ' && ((fmt->type == 'o' && len > fmt->precision)
		|| fmt->type != 'o'))
		apply_hash(fmt);
}

void				apply_case(char buf[64], t_fmt *fmt, int len)
{
	int i;

	if (fmt->type == 'X')
	{
		i = 0;
		while (i < len)
		{
			buf[64 - len + i] = ft_toupper(buf[64 - len + i]);
			i++;
		}
	}
}

long long unsigned	apply_unsigned_cast(t_fmt *fmt, va_list args)
{
	uintmax_t number;

	if (fmt->z)
		number = va_arg(args, size_t);
	else if (fmt->j)
		number = va_arg(args, uintmax_t);
	else if (fmt->length == -2)
		number = (unsigned char)va_arg(args, unsigned int);
	else if (fmt->length == -1)
		number = (unsigned short)va_arg(args, unsigned int);
	else if (fmt->length == 0)
		number = va_arg(args, unsigned int);
	else if (fmt->length == 1)
		number = va_arg(args, unsigned long);
	else
		number = va_arg(args, unsigned long long);
	return (number);
}

void				print_unsigned(t_fmt *fmt, va_list args, int base)
{
	int					len;
	char				buf[64];
	long long unsigned	number;

	if (fmt->type == 'p')
	{
		fmt->hash = 1;
		fmt->length = 1;
	}
	else if (fmt->type == 'U' || fmt->type == 'O')
		fmt->length = 1;
	number = apply_unsigned_cast(fmt, args);
	if (fmt->minus == 1)
		fmt->filler = ' ';
	fmt->null = (number ? 0 : 1);
	len = ft_utoa_base(number, base, buf);
	apply_prefix(fmt, len);
	apply_case(buf, fmt, len);
	print_buf(buf, fmt, len);
	apply_postfix(fmt);
}
