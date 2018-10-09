#include <stdio.h>
#include <time.h>
#include <string.h>
#include "global.h"

/* Размер и число тестовых блоков. */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

static void MDString PROTO_LIST ((char *));
static void MDTimeTrial PROTO_LIST ((void));
static void MDTestSuite PROTO_LIST ((void));
static void MDFile PROTO_LIST ((char *));
static void MDFilter PROTO_LIST ((void));
static void MDPrint PROTO_LIST ((unsigned char [16]));

/* Драйвер.
Аргументы (допускаются любые комбинации):
  -sstring — строка сигнатур
  -t - определять время
  -x - использовать тестовый сценарий
  filename — файл сигнатур
  (none) - стандартный ввод для сигнатур
 */
int main (int argc, char **argv)
{
  int i;

  if (argc > 1)
 	for (i = 1; i < argc; i++)
   		if (argv[i][0] == '-' && argv[i][1] == 's')
     		MDString (argv[i] + 2);
   		else if (strcmp (argv[i], "-t") == 0)
     		MDTimeTrial ();
   		else if (strcmp (argv[i], "-x") == 0)
     		MDTestSuite ();
   		else
     		MDFile (argv[i]);
  else
  	MDFilter ();
  return (0);
}

/* Создает и выводит сигнатуру. */
static void MDString (string) char *string;
{
  MD_CTX context;
  unsigned char digest[16];
  unsigned int len = strlen (string);

  MDInit (&context);
  MDUpdate (&context, string, len);
  MDFinal (digest, &context);

  printf ("MD%d (\"%s\") = ", MD, string);
  MDPrint (digest);
  printf ("\n");
}

/* Измерение времени создания сигнатуры для TEST_BLOCK_COUNT блоков по
   TEST_BLOCK_LEN байтов.
 */
static void MDTimeTrial ()
{
  MD_CTX context;
  time_t endTime, startTime;
  unsigned char block[TEST_BLOCK_LEN], digest[16];
  unsigned int i;
  printf
 ("MD%d time trial. Digesting %d %d-byte blocks ...", MD,
  TEST_BLOCK_LEN, TEST_BLOCK_COUNT);

  /* Инициализация блока */
  for (i = 0; i < TEST_BLOCK_LEN; i++)
 block[i] = (unsigned char)(i & 0xff);

  /* Запуск таймера */
  time (&startTime);

  /* Создание сигнатур блоков */
  MDInit (&context);
  for (i = 0; i < TEST_BLOCK_COUNT; i++)
 MDUpdate (&context, block, TEST_BLOCK_LEN);
  MDFinal (digest, &context);

  /* Остановка таймера */
  time (&endTime);

  printf (" done\n");
  printf ("Digest = ");
  MDPrint (digest);
  printf ("\nTime = %ld seconds\n", (long)(endTime-startTime));
  printf
 ("Speed = %ld bytes/second\n",
  (long)TEST_BLOCK_LEN * (long)TEST_BLOCK_COUNT/(endTime-startTime));
}

/* Создает сигнатуры тестовых строк и выводит результаты. */
static void MDTestSuite ()
{
  printf ("MD%d test suite:\n", MD);

  MDString ("");
  MDString ("a");
  MDString ("abc");
  MDString ("message digest");
  MDString ("abcdefghijklmnopqrstuvwxyz");
  MDString
 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  MDString
 ("1234567890123456789012345678901234567890\
1234567890123456789012345678901234567890");
}

/* Создает и выводит сигнатуру файла. */
static void MDFile (filename)
char *filename;
{
  FILE *file;
  MD_CTX context;
  int len;
  unsigned char buffer[1024], digest[16];

  if ((file = fopen (filename, "rb")) == NULL)
 printf ("%s can't be opened\n", filename);

  else {
 MDInit (&context);
 while (len = fread (buffer, 1, 1024, file))
   MDUpdate (&context, buffer, len);
 MDFinal (digest, &context);

 fclose (file);

 printf ("MD%d (%s) = ", MD, filename);
 MDPrint (digest);
 printf ("\n");
  }
}

/* Создает сигнатуру данных со стандартного ввода и выводит результат. */
static void MDFilter ()
{
  MD_CTX context;
  int len;
  unsigned char buffer[16], digest[16];

  MDInit (&context);
  while (len = fread (buffer, 1, 16, stdin))
 MDUpdate (&context, buffer, len);
  MDFinal (digest, &context);

  MDPrint (digest);
  printf ("\n");
}

/* Выводит цифровую подпись в шестнадцатеричном формате. */
static void MDPrint (digest)
unsigned char digest[16];
{
  unsigned int i;

  for (i = 0; i < 16; i++)
 printf ("%02x", digest[i]);
}