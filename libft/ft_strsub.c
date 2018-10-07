/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 16:39:15 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 16:17:10 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	size_t	i;
	char	*str;

	i = -1;
	if (!s)
		return (0);
	if ((str = malloc(sizeof(char) * (len + 1))))
	{
		while (++i < len)
			str[i] = s[start + i];
		str[i] = '\0';
		return (str);
	}
	return (NULL);
}
