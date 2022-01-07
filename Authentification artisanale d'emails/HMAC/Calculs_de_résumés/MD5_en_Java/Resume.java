// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;

public class Resume
{
    
    public static byte[] md5(String file){
        try {
            File fichier = new File(file);
            FileInputStream fis = new FileInputStream(fichier);

            MessageDigest hacheur = MessageDigest.getInstance("MD5");
            
            byte[] buffer = new byte[1024];
            int nbOctetsLus = fis.read(buffer);                   // Lecture du premier morceau
            while (nbOctetsLus != -1) {
                hacheur.update(buffer, 0, nbOctetsLus); // Digestion du morceau
                nbOctetsLus = fis.read(buffer);                   // Lecture du morceau suivant
            }
            fis.close();

            byte[] resumeMD5 = hacheur.digest();
            System.out.print("Le résumé MD5 du fichier \"butokuden.jpg\" vaut: 0x");
            for(byte k: resumeMD5)
                System.out.printf("%02x", k);
            System.out.println();
            return resumeMD5;
        } catch (Exception e) { e.printStackTrace(); }
        return null;
    }
    public static void main(String[] args)
    {
        md5("/home/yanis/Projects/Cryptographie/Authentification artisanale d'emails/HMAC/corps_avec_secret.txt");
    }
}

/* 
   $
   $ cat butokuden.jpg | md5
   aeef572459c1bec5f94b8d62d5d134b5
   $ javac Resume.java
   $ java Resume
   Le résumé MD5 du fichier "butokuden.jpg" vaut: 0xaeef572459c1bec5f94b8d62d5d134b5
   $
*/

