/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 15:31:40 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 16:14:11 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(char const *s, char (*f)(char))
{
	size_t	i;
	char	*str;

	i = -1;
	if (!s)
		return (0);
	if ((str = (char *)malloc(sizeof(char) * (1 + ft_strlen(s)))))
	{
		while (++i < ft_strlen(s))
			str[i] = f(s[i]);
		str[i] = '\0';
	}
	return (str);
}
