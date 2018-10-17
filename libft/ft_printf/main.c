/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 11:54:13 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/08/04 20:02:42 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	print_argument(t_fmt *fmt, va_list args)
{
	if (fmt->type == '%')
		print_percent(fmt);
	else if (fmt->type == 'C' || (fmt->type == 'c' && fmt->length == 1))
		print_unicode_char(fmt, va_arg(args, wchar_t));
	else if (fmt->type == 'c')
		print_char(fmt, va_arg(args, int));
	else if (fmt->type == 'S' || (fmt->type == 's' && fmt->length == 1))
		print_unicode_string(fmt, va_arg(args, wchar_t *));
	else if (fmt->type == 's')
		print_string(fmt, va_arg(args, char *));
	else if (fmt->type == 'o' || fmt->type == 'O')
		print_unsigned(fmt, args, 8);
	else if (fmt->type == 'd' || fmt->type == 'D' || fmt->type == 'i')
		print_signed(fmt, args, 10);
	else if (fmt->type == 'u' || fmt->type == 'U')
		print_unsigned(fmt, args, 10);
	else if (fmt->type == 'x' || fmt->type == 'X' || fmt->type == 'p')
		print_unsigned(fmt, args, 16);
}

int		ft_printf(const char *restrict format, ...)
{
	va_list		args;
	t_fmt		fmt;

	fmt.p = 0;
	fmt.printed = 0;
	va_start(args, format);
	while (format[fmt.p] != '\0')
	{
		if (format[fmt.p] == '%')
		{
			fmt.p++;
			parsing(format, &fmt, args);
		}
		else
		{
			ft_write(format[fmt.p], &fmt);
			fmt.p++;
		}
	}
	return (fmt.printed);
}
