import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Dpoac {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {



        dpoac(args[0], args[1]);



    }

    public static void dpoac(String src, String dst) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Mot de passe : ");
        String password = scanner.nextLine();
        byte[] P = constructSecretKey(password);
        RSAPrivateKey rsaPrivateKey = constructRSAPrivateKey("Clefs_POAC/POAC.pkcs8");
        byte[] cs = getSessionKey(src);
        byte[] vi = getVI(src);
        System.out.println("DPOAC vi : >> "+toHex(vi));
        byte[] clefSessionDecrypted = decryptKeyWithRSA(cs, rsaPrivateKey);
        System.out.println("DPOAC Clef d session : >> "+toHex(clefSessionDecrypted));
        byte[] r = decryptWithAES(src,clefSessionDecrypted,vi);
        System.out.println("DOAC Taille du fichier decrypté :> "+r.length);

        File test = new File(dst);
        try{
            FileOutputStream fos = new FileOutputStream(test);
            fos.write(r);
            fos.close();
        }catch(Exception e){}

        /** authentification */
        byte[] appendice = getResume(src);
        System.out.println();
        System.out.println("< "+toHex(appendice)+" >");
        System.out.println("< "+toHex(hmac(P,src))+" >");
        if(!Arrays.equals(appendice,hmac(P,src))){
            System.out.println();
            System.out.println("ENVOI CORROMPU");
        }


    }

    public static byte[] constructSecretKey(String key){
        byte[] k =  key.getBytes(StandardCharsets.UTF_8);
        return k;
    }


    public static RSAPrivateKey constructRSAPrivateKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        /* Lecture de l’encodage complet de la clef d’un seul coup ! */
        byte [] encodage = Files.readAllBytes(Paths.get(file));

        /* Analyse des sp´ecifications de la clef (D´ecodage) */
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodage);

        /* Fabrique de l’objet Key correspondant aux sp´ecifications */
        KeyFactory usine = KeyFactory.getInstance("RSA");
        RSAPrivateKey clefPrivee = (RSAPrivateKey) usine.generatePrivate(spec);
        return clefPrivee;

    }

    public static byte[] decryptKeyWithRSA(byte[] s, RSAPrivateKey clefPrive ) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher chiffreur = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        chiffreur.init(Cipher.DECRYPT_MODE, clefPrive);
        byte[] chiffre = chiffreur.doFinal(s); // On chiffre d’un coup
        System.out.println("Message dechiffr´e: 0x" + toHex(chiffre));
        return chiffre;

    }

    public static byte[] decryptWithAES(String src, byte[] clefSession, byte[] vi) throws InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec clefSecrete = null;
        Cipher chiffreur;
        byte[] fd = getFileData(src);
        System.out.println("DPOAC Taille du fichier crypté : "+fd.length);
        clefSecrete = new SecretKeySpec(clefSession, "AES");
        chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(vi);
        chiffreur.init(Cipher.DECRYPT_MODE, clefSecrete,ivspec);
        byte[] buffer = chiffreur.doFinal(fd);
        return buffer;

    }

    public static byte[] getSessionKey(String file) throws IOException {
        byte[] tab = Files.readAllBytes(Paths.get(file));
        byte[] cs = new byte[256];
        for(int i=0; i<256; i++){
            cs[i] = tab[i];
        }
        return cs;

    }

    public static byte[] getVI(String file) throws IOException {
        byte[] tab = Files.readAllBytes(Paths.get(file));
        byte[] vi = new byte[16];
        int j=0;
        for(int i=256; i<256+16; i++){
            vi[j] = tab[i];
            j++;
        }
        return vi;

    }

    public static byte[] getFileData(String file) throws IOException {
        byte[] tab = Files.readAllBytes(Paths.get(file));
        byte[] d = new byte[tab.length-32-256-16];

        int j=0;
        for(int i=256+16; i<tab.length-32; i++){
            d[j] = tab[i];
            j++;
        }
        return d;
    }

    public static byte[] getResume(String file) throws IOException {
        byte[] tab = Files.readAllBytes(Paths.get(file));
        byte[] resume = new byte[32];
        int j=0;
        for(int i=tab.length-32; i<tab.length; i++){
            resume[j] = tab[i];
            j++;
        }
        return resume;
    }


    public static String toHex(byte[] resume) {
        StringBuffer sb = new StringBuffer();
        for(byte k: resume) sb.append(String.format("%02X", k));
        return sb.toString();
    }

    public static byte[] hmac(byte[] secret, String file) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec clefSecrete =new SecretKeySpec(secret, "HmacSHA256");
        mac.init(clefSecrete);
        byte[] appendice = getResume(file);
        mac.update(appendice);
       // byte[] appendice = mac.doFinal();
        System.out.print("Le HMAC-SHA256 vaut: "+ toHex
                (appendice));
        return appendice;
    }



}
