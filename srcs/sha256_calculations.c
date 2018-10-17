#include "ft_ssl.h"

static const uint32_t k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void transformation_routine(t_sha256 *sha)
{
	int			i;
	uint32_t	t1;
	uint32_t	t2;

	i = 0;
	while (i < 64)
	{
		t1 = sha->h + EP1(sha->e) + CH(sha->e,sha->f,sha->g) + k[i] + sha->x[i];
		t2 = EP0(sha->a) + MAJ(sha->a,sha->b,sha->c);
		sha->h = sha->g;
		sha->g = sha->f;
		sha->f = sha->e;
		sha->e = sha->d + t1;
		sha->d = sha->c;
		sha->c = sha->b;
		sha->b = sha->a;
		sha->a = t1 + t2;
		i++;
	}
}

void	sha256_transform(t_sha256 *sha, unsigned char block[64])
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	while (i < 16)
	{
		sha->x[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | (block[j + 3]);
		i++;
		j += 4;
	}
	while (i < 64)
	{
		sha->x[i] = SIG1(sha->x[i - 2]) + sha->x[i - 7] + SIG0(sha->x[i - 15]) + sha->x[i - 16];
		i++;
	}
	sha->a = sha->state[0];
	sha->b = sha->state[1];
	sha->c = sha->state[2]; 
	sha->d = sha->state[3];
	sha->e = sha->state[4];
	sha->f = sha->state[5];
	sha->g = sha->state[6];
	sha->h = sha->state[7];
	transformation_routine(sha);
	sha->state[0] += sha->a;
	sha->state[1] += sha->b;
	sha->state[2] += sha->c;
	sha->state[3] += sha->d;
	sha->state[4] += sha->e;
	sha->state[5] += sha->f;
	sha->state[6] += sha->g;
	sha->state[7] += sha->h;
}