/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/01 15:37:13 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 18:18:27 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t i;
	size_t dst_len;
	size_t src_len;

	i = 0;
	dst_len = 0;
	src_len = 0;
	while (dst[i++] != 0)
		dst_len++;
	i = 0;
	while (src[i++] != 0)
		src_len++;
	i = 0;
	if (size > dst_len)
	{
		while (size > dst_len + i + 1 && src[i])
		{
			dst[dst_len + i] = src[i];
			i++;
		}
		dst[dst_len + i] = '\0';
		return (src_len + dst_len);
	}
	else
		return (src_len + size);
}
