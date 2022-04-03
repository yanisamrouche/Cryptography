import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;


public class Poac {


    public static void main( String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        poac(args[0],args[1]);
    }

    public static void poac(String src, String dst) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Mot de passe : ");
        String password = scanner.nextLine();
        /** les 256 octets du chiffrement RSA de la clef de session choisie ; */
        byte[] clefSession = randomKey();
        System.out.println("POAC Clef d session : >> "+toHex(clefSession));
        RSAPublicKey rsaPublicKey = constructRSAPublicKey("Clefs_POAC/POAC.x509");
        byte[] clefSessionCrypted =  encryptKeyWithRSA(clefSession, rsaPublicKey);
        /** les 16 octets du vecteur d’initialisation IV choisi ; */
        byte[] iv = randomKey();
        System.out.println("POAC vi : >> "+toHex(iv));
        /** les octets correspondant au chiffré par AES en mode CBC du fichier indiqué en paramètre ; */
        byte[] aes = encryptWithAES(src,clefSession,iv);
        System.out.println("POAC Taille du fichier crypté : "+aes.length);
        /** hmac */
        byte[] P = constructSecretKey(password);
        byte[] appendice = hmac(P, src);
        /** construire le fichier .poac */
        ByteBuffer bb = ByteBuffer.allocate(clefSessionCrypted.length + iv.length + aes.length + appendice.length);
        bb.put(clefSessionCrypted); bb.put(iv); bb.put(aes);bb.put(appendice);
        byte[] result = bb.array();
        File test = new File(dst);
        try{
            FileOutputStream fos = new FileOutputStream(test);
            fos.write(result);
            fos.close();
        }catch(Exception e){}



    }
    /** construction du secret sous la forme d’une suite d’octets
     * à partir du mot-de-passe  */
    public static byte[] constructSecretKey(String key){
        byte[] k =  key.getBytes(StandardCharsets.UTF_8);
        /*
        byte[] k = new byte[key.length()];
        for(int i=0; i<key.length(); i++){
            char c = key.charAt(i);
            int ascii = (int) c;
            k[i] = (byte) ascii;
        }
        //System.out.print("la clé "+key+" en ASCII = ");
        for(int i=0; i<key.length(); i++){
            //System.out.print(k[i]+" ");
        }

         */
        return k;
    }

    /** choix de 16
     octets aléatoires pour la clef de session ou le vecteur d’initialisation */
    public static byte[] randomKey(){
        // Pour choisir des suites d’octets al´eatoires
        SecureRandom alea = new SecureRandom();
        // Choix d’une suite de 16 octets formant la clef secr`ete
        byte[] clef = new byte[16];
        alea.nextBytes(clef); // remplit la clef d’octets al´eatoires
        // Construction de la (sp´ecification de la) clef secr`ete
        SecretKeySpec clefSecrete = new SecretKeySpec(clef, "AES");
        return clefSecrete.getEncoded();

    }


    /** fabrique de la clef RSA publique à partir
     des constantes fournies
     * @return*/

    public static RSAPublicKey constructRSAPublicKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        /* Lecture de l’encodage complet de la clef d’un seul coup ! */
        byte [] encodage = Files.readAllBytes(Paths.get(file));

        /* Analyse des sp´ecifications de la clef (D´ecodage) */
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodage);

        /* Fabrique de l’objet Key correspondant aux sp´ecifications */
        KeyFactory usine = KeyFactory.getInstance("RSA");
        RSAPublicKey clefPublique = (RSAPublicKey) usine.generatePublic(spec);
        return clefPublique;

    }

    /** chiffrer par RSA la clef de session choisie à l’aide d’une clef publique déterminée, qui apparaitra
     comme une constante dans le programme ;*/

    public static byte[] encryptKeyWithRSA(byte[] s, RSAPublicKey clefPublique ) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher chiffreur = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        chiffreur.init(Cipher.ENCRYPT_MODE, clefPublique);
        byte[] chiffre = chiffreur.doFinal(s); // On chiffre d’un coup
        System.out.println("Message chiffr´e: 0x" + toHex(chiffre));
        return chiffre;

    }

    /** Resume */
    public static byte[] resume(String file) throws IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream(file);
        MessageDigest hacheur = MessageDigest.getInstance("SHA1");
        byte[] buffer = new byte[1024];
        int nbOctetsLus = fis.read(buffer); // Lecture du premier morceau
        while ( nbOctetsLus != -1 ) {
            hacheur.update(buffer, 0, nbOctetsLus); // Digestion du morceau
            nbOctetsLus = fis.read(buffer); // Lecture du morceau suivant
        }
        byte[] resume = hacheur.digest();
        System.out.println("Le r´esum´e MD5 vaut: 0x" + toHex(resume));
        fis.close();
        return resume;
    }

    public static String toHex(byte[] resume) {
        StringBuffer sb = new StringBuffer();
        for(byte k: resume) sb.append(String.format("%02X", k));
        return sb.toString();
    }

    /** chiffrement */

    public static byte[] encryptWithAES(String src,byte[] clefSession, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] b = Files.readAllBytes(Paths.get(src));

        SecretKeySpec clefSecrete;
        Cipher chiffreur;
        FileInputStream fis; // Nous allons lire un fichier
        FileOutputStream fos; // et ´ecrire dans un autre
        byte[] buffer = new byte[1024]; // par morceaux.
        int nbOctetsLus;
        CipherInputStream cis;
        clefSecrete = new SecretKeySpec(clefSession, "AES");
        chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        chiffreur.init(Cipher.ENCRYPT_MODE, clefSecrete, ivspec);
        buffer = chiffreur.doFinal(b);
        fis = new FileInputStream(src);
        cis = new CipherInputStream(fis, chiffreur);
        fis.close();cis.close();
        return buffer;

    }




    public static byte[] hmac(byte[] secret, String file) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        FileInputStream fis = new FileInputStream(file);
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec clefSecrete =new SecretKeySpec(secret, "HmacSHA256");
        mac.init(clefSecrete);
        byte[] buffer = new byte[1024];
        int nbOctetsLus;
        while ( (nbOctetsLus = fis.read(buffer)) != -1 ) {
            mac.update(buffer, 0, nbOctetsLus);
        }
        byte[] appendice = mac.doFinal();
        System.out.print("Le HMAC-SHA256 vaut: "+ toHex
                                (appendice));
        return appendice;
    }













}
