import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class MonRC4 {
    private static int LG_FLUX = 467796;
    //static byte[] clef = {(byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5};
    static byte[] clef = keyToASCII("KYOTO");


    //Etat interne de RC4
    static byte[] state = new byte[256];
    static int i=0, j=0;

    //RFC 2104

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        //encrypt();

        /**
        //le secret partagé
        byte[] S = new byte[20];
        for(int i=0; i < 20; i++){
            S[i] = (byte) 0x0b;
        }
        //message
        byte[] c = {0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65};
        System.out.println("========= HMAC CONFORME A LA RFC 2104 ==========");
        byte[] r = HMAC_SHA256(c, S);
        System.out.println("========= DERIVATION D'UNE CLEF SECRETE A PARTIR D'UN MDP ==========");
        byte[] Pp = keyToASCII("Password");
        byte[] ss = keyToASCII("NaCl");
        byte [] res = PBKDF2_rec(Pp,ss,80000);

        System.out.println("=============================================================================================");
        System.out.println("Le mot de passe : Password");
        System.out.println("Le sel : NaCl");
        System.out.println("#itérations : 80000");
        System.out.println("La clef");
        for(byte k: res)
            System.out.printf("0x%02x ", k);
        System.out.println();
        System.out.println("=============================================================================================");
        */

        Scanner sc = new Scanner(System.in);

        if(args.length < 3){
            System.out.println("Usage : java MonRC4 -c src dst");
            System.exit(0);
        }

        switch (args[0]){
            case "-c":
                System.out.println("chiffrement...");
                System.out.print("mot de passe : ");
                String password_c = sc.nextLine();
                byte[] P = keyToASCII(password_c);
                String salt="";
                Random rand = new Random();
                for(int i=0; i<4; i++){
                    char b = (char) (rand.nextInt(26) + 97);
                    salt += b;
                }
                byte[] s = keyToASCII(salt);
                String S = new String(s, StandardCharsets.UTF_8);
                byte[] key = PBKDF2_rec(P,s,1000);
                encrypt(key, args[1],args[2]+"."+S+".rc4");
                break;
            case "-d":
                System.out.println("déchiffrement...");
                System.out.print("mot de passe : ");
                String password_d = sc.nextLine();
                byte[] P_d = keyToASCII(password_d);
                System.out.print("le sel : ");
                String s1 = sc.nextLine();
                byte[] s_d = keyToASCII(s1);
                byte[] k = PBKDF2_rec(P_d,s_d,100);
                decrypt(k,args[1], args[2]);
                break;

        }
    }

    /* ========================================================= EXO 01 ================================================================================================= */

    public static byte[] sha256(byte[] s) throws NoSuchAlgorithmException {
        MessageDigest msg = MessageDigest.getInstance("SHA-256");
        byte[] hash = msg.digest(s);
        return hash;
    }
    public static byte[] rightConcatination(byte[] S, byte[] c) throws NoSuchAlgorithmException {
        byte[] xorResult = new byte[64];
        byte[] concat = new byte[xorResult.length+c.length];
        byte[] compS = new byte[64];
        byte[] ipad = new byte[64];
        for(int i=0; i < 64; i++){
            ipad[i] = (byte) 0x36;
        }
        if(S.length < 64){
            for(int i=0; i < S.length; i++){
                compS[i] = S[i];
            }
            for (int i=S.length; i < compS.length; i++){
                compS[i] = (byte) 0x00;
            }
        }else {
            compS = sha256(S);
            for (int i=compS.length; i < 64; i++){
                compS[i] = (byte) 0x00;
            }
        }
        for (int i=0; i < compS.length; i++){
            xorResult[i] = (byte) (compS[i] ^ ipad[i]);
            concat[i] = xorResult[i];
        }
        int kk=0;
        for(int i=xorResult.length; i<concat.length; i++){
            concat[i] = c[kk];
            kk++;
        }
        for(byte k: concat)
            System.out.printf("%02x ", k);
        System.out.println();
        System.out.println("=======================================================");
        byte[] result = sha256(concat);
        for(byte k: result)
            System.out.printf("%02x ", k);
        System.out.println();
        return result;

    }

    public static byte[] leftConcatination(byte[] S) throws NoSuchAlgorithmException {
        byte[] result = new byte[64];
        byte[] compS = new byte[64];
        byte[] opad = new byte[64];
        for(int i=0; i < 64; i++){
            opad[i] = (byte) 0x5c;
        }
        if(S.length < 64){
            for(int i=0; i < S.length; i++){
                compS[i] = S[i];
            }
            for (int i=S.length; i < compS.length; i++){
                compS[i] = (byte) 0x00;
            }
        }else {
            compS = sha256(S);
            for (int i=compS.length; i < 64; i++){
                compS[i] = (byte) 0x00;
            }
        }
        for(int i=0; i < compS.length; i++){
            result[i] = (byte) (compS[i] ^ opad[i]);
        }
        return result;
    }

    public static byte[] HMAC_SHA256(byte[] c, byte[] S) throws NoSuchAlgorithmException {
        byte[] right = rightConcatination(S, c);
        byte[] left = leftConcatination(S);
        byte[] concatResult = new byte[left.length+right.length];
        for(int i=0; i < concatResult.length; i++){
            concatResult[i] = i < left.length ? left[i] : right[i - left.length];
        }
        System.out.println("=======================================================");
        for(byte k: concatResult)
            System.out.printf("%02x ", k);
        System.out.println();
        byte[] result = sha256(concatResult);
        System.out.println("=======================================================");
        for(byte k: result)
            System.out.printf("%02x ", k);
        System.out.println();
        return result;
    }

    /* ========================================================= EXO 02 ================================================================================================= */

    public static byte[] PBKDF2_rec(byte[] P, byte[] s, int n) throws NoSuchAlgorithmException {
        byte[] concat = new byte[s.length+4];
        byte[] o = {0x00, 0x00, 0x00, 0x01};
        byte[] res = new byte[32];
        List<byte[]> Us = new ArrayList<>();
        for(int i=0; i < concat.length; i++){
            concat[i] = i < s.length ? s[i] : o[i - s.length];
        }
        byte[] U = HMAC_SHA256(concat,P);
        Us.add(U);
        byte[] newU = U;
        for(int i=1; i<n; i++){
            byte[] u = HMAC_SHA256(newU,P);
            Us.add(u);
            newU = u;
        }
        byte[] u = Us.get(0);
        for(int i=1; i < Us.size(); i=i+1){
            byte[] u_ = Us.get(i);
            for(int j=0; j < res.length; j++){
                res[j] = (byte) (u[j] ^ u_[j]);
            }
            u = res;
        }
        return u;

    }



    /* ================================================================== RC4 ======================================================================================== */
    public static void encrypt(byte[] key, String src, String dst) throws IOException {
        initialisation(key);
        System.out.println("Premiers octets de la clef longue : ");
        byte[] clef_longue = new byte[LG_FLUX];
        for(int k=0; k < LG_FLUX; k++){
            //System.out.printf("0x%02X", production());
            clef_longue[k] = production();
        }
        System.out.println("\n");

        // src : Fabrique de clefs symétriques longues/RC4/Java/src/butokuden.jpg
        byte[] f = parseFile(src);
        byte[] newF = new byte[f.length];
        System.out.println(f.length);
        for(int i=0; i < f.length; i++){
            int xor = f[i] ^ clef_longue[i];
            newF[i] = (byte) xor;

        }
        /*
        for(int i=0; i < newF.length; i++){System.out.printf(newF[i]+" ");}
        */
        // dst : "confidentiel.jpg"
        byteToFile(dst, newF);

        //byte[] resume = resume("confidentiel.jpg", "MD5");


    }
    public static void decrypt(byte[] key, String src, String dst) throws IOException{
        initialisation(key);
        System.out.println("Premiers octets de la clef longue : ");
        byte[] clef_longue = new byte[LG_FLUX];
        for(int k=0; k < LG_FLUX; k++){
            // System.out.printf("0x%02X", production());
            clef_longue[k] = production();
        }
        System.out.println("\n");
        // src : "confidentiel.jpg"
        byte[] conf = parseFile(src);
        byte[] newConf = new byte[conf.length];
        for(int i=0; i < conf.length; i++){
            int xor = conf[i] ^ clef_longue[i];
            newConf[i] = (byte) xor;
        }
        // dst : newButokuden.jpg
        byteToFile(dst, newConf);
    }

    private static void echange(int k, int l){
        byte temp = state[k];
        state[k] = state[l];
        state[l] = temp;
    }

    private static void initialisation(byte[] clef){
        //int lg = clef.length;
        int lg = clef.length;
        System.out.println("\nclef courte utilisée");
        for(int k=0; k<lg; k++){
            System.out.print(String.format("0x%02X",clef[k]));
        }
        System.out.println("\nLongueur de la clef courte : "+lg);
        for(i=0; i<256; i++){
            state[i] = (byte) i;
        }
        j =0;
        for (int i=0; i<256; i++){
            j = (j + Byte.toUnsignedInt(state[i]) +Byte.toUnsignedInt(clef[i % lg])) % 256;
            echange(i, j);
        }
        i = 0;
        j = 0;
    }

    private static byte production(){
        i = (i+1) % 256;
        j = (j + Byte.toUnsignedInt(state[i])) % 256;
        echange(i, j);
        byte w = state[(Byte.toUnsignedInt(state[i]) + Byte.toUnsignedInt(state[j])) % 256];
        return w;
    }

    private static byte[] keyToASCII(String key){
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
        return k;
    }

    private static byte[] parseFile(String file){
        try{
            byte[] tab = Files.readAllBytes(Paths.get(file));

            //System.out.print(Arrays.toString(tab));
            return tab;
        }catch(IOException e){
            System.out.print(e.toString());
        }
        return null;

    }

    private static void byteToFile(String file, byte[] b) throws IOException{
        Path p = Paths.get(file);
        Files.write(p, b);
    }



}

