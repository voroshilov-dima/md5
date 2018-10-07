/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 21:11:44 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 16:27:32 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_length(int n)
{
	int len;

	len = 0;
	while (n && ++len)
		n = n / 10;
	return (len);
}

static int	ft_abs(int n)
{
	if (n < 0)
		return (-n);
	return (n);
}

char		*ft_itoa(int n)
{
	int		i;
	int		len;
	char	*str;

	i = 0;
	len = ft_length(n);
	str = 0;
	if (n <= 0)
		len++;
	if ((str = (char *)malloc(sizeof(char) * (len + 1))))
	{
		str[len] = 0;
		if (n == 0 && (str[0] = '0'))
			return (str);
		if (n < 0)
			str[0] = '-';
		while (n && i < len)
		{
			str[len - i - 1] = ft_abs(n % 10) + 48;
			n = n / 10;
			i++;
		}
	}
	return (str);
}
