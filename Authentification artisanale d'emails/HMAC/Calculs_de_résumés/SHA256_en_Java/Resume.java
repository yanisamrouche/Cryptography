// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;

public class Resume
{
    public static void main(String[] args)
    {
        try {
            File fichier = new File("butokuden.jpg");
            FileInputStream fis = new FileInputStream(fichier);

            MessageDigest hacheur = MessageDigest.getInstance("SHA-256");
            
            byte[] buffer = new byte[1024];
            int nbOctetsLus = fis.read(buffer);                   // Lecture du premier morceau
            while (nbOctetsLus != -1) {
                hacheur.update(buffer, 0, nbOctetsLus); // Digestion du morceau
                nbOctetsLus = fis.read(buffer);                   // Lecture du morceau suivant
            }
            fis.close();

            byte[] resumeSHA256 = hacheur.digest();
            System.out.print("Le résumé SHA256 du fichier \"butokuden.jpg\" vaut: 0x");
            for(byte k: resumeSHA256)
                System.out.printf("%02x", k);
            System.out.println();
        } catch (Exception e) { e.printStackTrace(); }
    }
}

/* 
   $ cat butokuden.jpg | shasum -a 256
   515e23a8b1dd66a5529a03ec0378b857bdbda20626c21e17306c1a935e013249  -
   $ make
   javac *.java 
   $ java Resume
   Le résumé SHA256 du fichier "butokuden.jpg" vaut: 0x515e23a8b1dd66a5529a03ec0378b857bdbda20626c21e17306c1a935e013249
   $ 
*/

