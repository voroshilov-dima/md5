/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/05 14:58:23 by dvoroshy          #+#    #+#             */
/*   Updated: 2016/12/05 16:23:07 by dvoroshy         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list *list;
	t_list *temp;

	if (!lst)
		return (NULL);
	list = f(lst);
	temp = list;
	while (lst->next)
	{
		list->next = f(lst->next);
		list = list->next;
		lst = lst->next;
	}
	return (temp);
}
