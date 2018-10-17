/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 18:48:15 by dvoroshy          #+#    #+#             */
/*   Updated: 2018/10/06 16:38:16 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <stdio.h>
# include <stdarg.h>
# include <stdlib.h>
# include "../libft.h"

typedef struct	s_fmt {
	char	type;
	int		space;
	int		minus;
	int		plus;
	int		hash;
	char	filler;
	int		width;
	int		length;
	int		precision;
	int		z;
	int		j;
	int		null;
	int		negative;
	int		printed;
	int		printed_current;
	int		p;
}				t_fmt;

char			mask_and_shift(wchar_t *c);
void			parsing(const char *restrict format, t_fmt *fmt, va_list args);
void			print_unsigned(t_fmt *fmt, va_list args, int base);
void			print_signed(t_fmt *fmt, va_list args, int base);
void			print_unicode_string(t_fmt *fmt, wchar_t *str);
void			print_buf(char buf[64], t_fmt *fmt, int len);
void			print_filler(t_fmt *fmt, int filler_length);
void			print_argument(t_fmt *fmt, va_list args);
void			print_string(t_fmt *fmt, char *str);
void			print_char(t_fmt *fmt, int c);
void			ft_write(char c, t_fmt *fmt);
void			clear_structure(t_fmt *fmt);
void			apply_postfix(t_fmt *fmt);
void			print_percent(t_fmt *fmt);
void			set_filler(t_fmt *fmt);
void			print_sign(t_fmt *fmt);
void			apply_hash(t_fmt *fmt);
int				ft_utoa_base(uintmax_t n, int base, char buf[64]);
int				print_unicode_char(t_fmt *fmt, wchar_t c);
int				get_precision(const char *restrict f, t_fmt *fmt, va_list args);
int				get_width(const char *restrict f, t_fmt *fmt, va_list args);

#endif
