/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_non_numbers.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/15 09:11:13 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/09/15 09:11:15 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void		print_percent(t_fmt *fmt)
{
	int		filler_length;

	filler_length = fmt->width - 1;
	if (filler_length && fmt->minus == 0)
		print_filler(fmt, filler_length);
	ft_write('%', fmt);
	if (filler_length && fmt->minus)
		apply_postfix(fmt);
}

void		print_char(t_fmt *fmt, int c)
{
	int		filler_length;

	filler_length = fmt->width - 1;
	if (filler_length && fmt->minus == 0)
		print_filler(fmt, filler_length);
	ft_write(c, fmt);
	if (filler_length && fmt->minus)
		apply_postfix(fmt);
}

void		print_string(t_fmt *fmt, char *str)
{
	int			i;
	int			filler_length;
	static char	nul[6] = "(null)";

	if (str == NULL)
		str = nul;
	if (fmt->precision != -1)
		str = ft_strsub(str, 0, fmt->precision);
	filler_length = fmt->width - ft_strlen(str);
	if (filler_length && fmt->minus == 0)
		print_filler(fmt, filler_length);
	i = 0;
	while (*str && (fmt->precision == -1 || i < fmt->precision))
	{
		ft_write(*str, fmt);
		str++;
		i++;
	}
	if (filler_length && fmt->minus)
		apply_postfix(fmt);
}
