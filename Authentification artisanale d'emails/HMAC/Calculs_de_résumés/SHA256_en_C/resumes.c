// -*- coding: utf-8 -*-

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

int main(void)
{
  char *nom_du_fichier = "butokuden.jpg";
  FILE *fichier = fopen (nom_du_fichier, "rb");
  if (fichier == NULL) {
    printf ("Le fichier %s ne peut pas être ouvert.\n", nom_du_fichier);
    exit(EXIT_FAILURE);
  }

  SHA256_CTX contexte;
  SHA256_Init (&contexte);

  unsigned char buffer[1024];
  int nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier); // Lecture du premier morceau
  while (nb_octets_lus != 0) {
    SHA256_Update (&contexte, buffer, nb_octets_lus);                // Digestion du morceau
    nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier);   // Lecture du morceau suivant
  }
  fclose (fichier);

  unsigned char resume[SHA256_DIGEST_LENGTH];
  SHA256_Final (resume, &contexte);
  printf("Le résumé SHA256 du fichier \"butokuden.jpg\" vaut: 0x");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", resume[i]);
  printf("\n");
  exit(EXIT_SUCCESS);
}

/*
  $ shasum -a 256 butokuden.jpg 
  515e23a8b1dd66a5529a03ec0378b857bdbda20626c21e17306c1a935e013249  butokuden.jpg
  $ make
  gcc -o resumes -I/usr/local/include -I/usr/include resumes.c -L/usr/local/lib -L/usr/lib
  -lm -lssl -lcrypto -g -std=c99 -Wall
  $ ./resumes 
  Le résumé SHA256 du fichier "butokuden.jpg" vaut: 0x515e23a8b1dd6...3249
  $
*/
