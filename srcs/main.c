#include "ft_ssl.h"

int	main(int argc, char **argv)
{
	int		i;

	i = 1;
	if (argc < 2)
		printf("Choose algorithm\n");
	else if (ft_strcmp(argv[1], "md5") == 0)
		md5(argc, argv);
	else if (ft_strcmp(argv[1], "sha256") == 0)
		sha256(argc, argv);
	else
		printf("The program supports following algorithms: md5, sha256\n");
	return (0);
}
