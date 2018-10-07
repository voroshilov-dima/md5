/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 18:13:36 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/06 12:29:15 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static	char	*fill(char const *s, int len, int start, int end)
{
	int		i;
	char	*str;

	i = 0;
	len = ft_strlen(s);
	if ((str = (char *)malloc(sizeof(char) * (len - end - start + 1))))
	{
		while (i < len - end - start)
		{
			str[i] = s[start + i];
			i++;
		}
		str[i] = '\0';
		return (str);
	}
	else
		return (NULL);
}

char			*ft_strtrim(char const *s)
{
	int i;
	int start;
	int end;
	int len;

	i = 0;
	start = 0;
	end = 0;
	if (!s)
		return (NULL);
	while (s[i] != '\0' && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t'))
	{
		start++;
		i++;
	}
	i = 0;
	len = ft_strlen(s);
	if (start != len)
		while (s[len - i - 1] == ' ' ||
				s[len - i - 1] == '\n' || s[len - i - 1] == '\t')
		{
			end++;
			i++;
		}
	return (fill(s, len, start, end));
}
