/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strswap.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/06 16:09:52 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/06 17:14:07 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strswap(char *s)
{
	int		i;
	int		j;
	char	*str;

	i = 0;
	j = 0;
	while (*(s + i))
		i++;
	str = (char *)malloc(sizeof(char) * (i + 1));
	while (i != 0)
		str[j++] = s[i-- - 1];
	str[j] = '\0';
	return (str);
}
