/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/02 19:29:20 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/06 17:46:27 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		fill(char **array, char const *s, char c, int words)
{
	int i;
	int j;

	j = 0;
	while (j < words)
	{
		i = 0;
		while (*s == c)
			s++;
		while (*s != c && *s != '\0')
		{
			(*array)[i] = *s;
			i++;
			s++;
		}
		(*array)[i] = '\0';
		array++;
		j++;
	}
}

static void		alloc(char **array, char const *s, char c, int words)
{
	int i;
	int j;

	j = 0;
	while (j < words)
	{
		i = 0;
		while (*s == c)
			s++;
		while (*s != c && *s != '\0')
		{
			i++;
			s++;
		}
		if (!(*array = (char *)malloc(sizeof(char) * (i + 1))))
			return ;
		array++;
		j++;
	}
}

static void		to_list(t_list **list, char **array)
{
	*list = ft_lstnew(*array, ft_strlen(*array));
	if (!(*array++))
		return ;
	while (*array)
	{
		(*list)->next = ft_lstnew(*array, ft_strlen(*array) + 1);
		list = &((*list)->next);
		array++;
	}
}

t_list			*ft_strsplit_lst(char const *s, char c)
{
	int		i;
	int		words;
	char	**array;
	t_list	*list;

	i = -1;
	words = 0;
	array = 0;
	if (!s)
		return (NULL);
	while (s[++i])
		if (s[i] != c && ((s[i + 1] == c) || s[i + 1] == '\0'))
			words++;
	if ((array = (char **)malloc(sizeof(char *) * (words + 1))))
	{
		array[words] = 0;
		alloc(array, s, c, words);
		fill(array, s, c, words);
		to_list(&list, array);
		free(array);
		return (list);
	}
	return (NULL);
}
