/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   support_functions3.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/06 15:43:23 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/10/06 15:43:24 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int		process_wildcard(t_fmt *fmt, va_list args, int mode)
{
	if (mode == 0)
	{
		fmt->width = va_arg(args, int);
		if (fmt->width < 0)
		{
			fmt->minus = 1;
			fmt->width = -fmt->width;
		}
	}
	else if (mode == 1)
	{
		fmt->precision = va_arg(args, int);
		if (fmt->precision < 0)
			fmt->precision = -1;
	}
	return (1);
}

int		get_width(const char *restrict f, t_fmt *fmt, va_list args)
{
	int	i;
	int wildcard;

	i = 0;
	wildcard = 0;
	while ((f[fmt->p + i] >= 48 && f[fmt->p + i] <= 57)
		|| f[fmt->p + i] == 42)
	{
		if (f[fmt->p + i] == 42)
			wildcard = process_wildcard(fmt, args, 0);
		else if (wildcard)
		{
			fmt->width = f[fmt->p + i] - 48;
			wildcard = 0;
		}
		else
			fmt->width = fmt->width * 10 + f[fmt->p + i] - 48;
		i++;
	}
	return (i);
}

int		get_precision(const char *restrict f, t_fmt *fmt, va_list args)
{
	int	i;
	int wildcard;

	i = 1;
	wildcard = 0;
	fmt->precision = 0;
	while ((f[fmt->p + i] >= 48 && f[fmt->p + i] <= 57)
		|| f[fmt->p + i] == 42)
	{
		if (f[fmt->p + i] == 42)
			wildcard = process_wildcard(fmt, args, 1);
		else if (fmt->precision == -1 || wildcard)
		{
			fmt->precision = f[fmt->p + i] - 48;
			wildcard = 0;
		}
		else
			fmt->precision = fmt->precision * 10 + f[fmt->p + i] - 48;
		i++;
	}
	return (i);
}
