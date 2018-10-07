/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/01 17:44:05 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/01 20:37:14 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	int i;
	int index;

	i = 0;
	index = -1;
	while (s[i] != '\0')
		if (s[i++] == (char)c)
			index = i - 1;
	if (s[i] == (char)c)
		return ((char *)(s + i));
	if (index >= 0)
		return ((char *)(s + index));
	return (NULL);
}
