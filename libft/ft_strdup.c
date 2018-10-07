/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/01 13:38:46 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/01 20:32:00 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strdup(const char *s1)
{
	int		i;
	char	*str;

	i = 0;
	while (*(s1 + i) != '\0')
		i++;
	str = (char *)malloc(sizeof(char) * (i + 1));
	i = 0;
	if (str)
	{
		while (*(s1 + i) != '\0')
		{
			str[i] = s1[i];
			i++;
		}
		str[i] = '\0';
	}
	else
		return (NULL);
	return (str);
}
