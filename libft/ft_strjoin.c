/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 17:49:41 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/02 18:12:54 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	int		i;
	char	*str;

	i = 0;
	if (s1 && s2 && (str = malloc(sizeof(char) *
					(ft_strlen(s1) + ft_strlen(s2) + 1))))
	{
		while (*s1)
			*(str + i++) = *s1++;
		while (*s2)
			*(str + i++) = *s2++;
		*(str + i) = '\0';
		return (str);
	}
	return (NULL);
}
