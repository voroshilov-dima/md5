#ifndef FT_SSL_H
# define FT_SSL_H

# define S11 7
# define S12 12
# define S13 17
# define S14 22
# define S21 5
# define S22 9
# define S23 14
# define S24 20
# define S31 4
# define S32 11
# define S33 16
# define S34 23
# define S41 6
# define S42 10
# define S43 15
# define S44 21

# include <stdio.h>
# include "libft.h"

typedef struct {
  unsigned long	state[4];
  unsigned long		count[2];
  unsigned char		buffer[64];
} MD5_CTX;

#endif