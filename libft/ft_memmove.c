/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/30 16:26:55 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 18:09:59 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	size_t i;

	i = 0;
	while (len--)
		if (dst > src)
			*(char *)(dst + len) = *(char *)(src + len);
		else
		{
			*(char *)(dst + i) = *(char *)(src + i);
			i++;
		}
	return (dst);
}
