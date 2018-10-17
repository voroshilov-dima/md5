/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_format.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/15 09:11:00 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/09/15 09:11:06 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int		is_specifier(char c, t_fmt *fmt)
{
	if (c == 's' || c == 'S' || c == 'p' || c == 'd' ||
		c == 'D' || c == 'i' || c == 'o' || c == 'O' ||
		c == 'u' || c == 'U' || c == 'x' || c == 'X' ||
		c == 'c' || c == 'C' || c == '%')
	{
		fmt->type = c;
		return (1);
	}
	return (0);
}

int		is_flag(const char *restrict f, t_fmt *fmt, va_list args, int i)
{
	if (f[fmt->p] == ' ')
		fmt->space += 1;
	else if (f[fmt->p] == '-')
		fmt->minus = 1;
	else if (f[fmt->p] == '+')
		fmt->plus = 1;
	else if (f[fmt->p] == '.')
		i = get_precision(f, fmt, args);
	else if ((f[fmt->p] >= 49 && f[fmt->p] <= 57) || f[fmt->p] == 42)
		i = get_width(f, fmt, args);
	else if (f[fmt->p] == '0')
		set_filler(fmt);
	else if (f[fmt->p] == 'l')
		fmt->length++;
	else if (f[fmt->p] == 'h')
		fmt->length--;
	else if (f[fmt->p] == '#')
		fmt->hash = 1;
	else if (f[fmt->p] == 'z')
		fmt->z = 1;
	else if (f[fmt->p] == 'j')
		fmt->j = 1;
	else
		i = 0;
	return (i);
}

void	print_unvalid(const char *restrict format, t_fmt *fmt)
{
	int	filler_length;

	filler_length = fmt->width - 1;
	if (filler_length && fmt->minus == 0)
		print_filler(fmt, filler_length);
	ft_write(format[fmt->p], fmt);
	if (filler_length && fmt->minus)
		apply_postfix(fmt);
}

void	parsing(const char *restrict format, t_fmt *fmt, va_list args)
{
	int	flag_length;
	int	i;

	clear_structure(fmt);
	while (format[fmt->p])
	{
		i = 1;
		flag_length = is_flag(format, fmt, args, i);
		if (flag_length)
			fmt->p += flag_length;
		else if (is_specifier(format[fmt->p], fmt))
		{
			print_argument(fmt, args);
			fmt->p++;
			return ;
		}
		else
		{
			print_unvalid(format, fmt);
			fmt->p++;
			return ;
		}
	}
}
