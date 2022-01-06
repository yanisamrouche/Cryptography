// -*- coding: utf-8 -*-

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

int main(void)
{
  char *nom_du_fichier = "butokuden.jpg";
  FILE *fichier = fopen (nom_du_fichier, "rb");
  if (fichier == NULL) {
    printf ("Le fichier %s ne peut pas être ouvert.\n", nom_du_fichier);
    exit(EXIT_FAILURE);
  }

  MD5_CTX contexte;
  MD5_Init (&contexte);

  unsigned char buffer[1024];
  int nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier); // Lecture du premier morceau
  while (nb_octets_lus != 0) {
    MD5_Update (&contexte, buffer, nb_octets_lus);                // Digestion du morceau
    nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier);   // Lecture du morceau suivant
  }
  fclose (fichier);

  unsigned char resume_md5[MD5_DIGEST_LENGTH];
  MD5_Final (resume_md5, &contexte);
  printf("Le résumé MD5 du fichier \"butokuden.jpg\" vaut: 0x");
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", resume_md5[i]);
  printf("\n");
  exit(EXIT_SUCCESS);
}

/*
$ cat butokuden.jpg | md5
aeef572459c1bec5f94b8d62d5d134b5
$ make
gcc -o resumes -I/usr/local/include -I/usr/include resumes.c -L/usr/local/lib -L/usr/lib -lm -lssl -lcrypto -g -std=c99 -Wall
$ ./resumes
Le résumé MD5 du fichier "butokuden.jpg" vaut: 0xaeef572459c1bec5f94b8d62d5d134b5
$
*/
