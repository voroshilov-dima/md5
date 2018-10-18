#include "ft_ssl.h"

int	main(int argc, char **argv)
{
	int					i;
	static t_algorithm	algorithms[3] = {{"md5", md5}, {"sha256", sha256}};

	i = 0;
	if (argc < 2)
		ft_printf("Choose algorithm\n");
	else
	{
		while (i < 3)
		{
			if (ft_strcmp(argv[1], algorithms[i].name) == 0)
			{
				algorithms[i].func(argc, argv);
				break ;
			}
			i++;
		}
		ft_printf("The program supports following algorithms: md5, sha256\n");
		exit (1);
	}	
	return (0);
}
