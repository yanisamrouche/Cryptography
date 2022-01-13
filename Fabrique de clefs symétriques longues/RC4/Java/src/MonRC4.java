import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class MonRC4 {
    private static int LG_FLUX =467796;
    //static byte[] clef = {(byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5};
    static byte[] clef = keyToASCII("KYOTO");


    //Etat interne de RC4
    static byte[] state = new byte[256];
    static int i=0, j=0;

    public static void main(String[] args) throws IOException{
        initialisation();
        System.out.println("Premiers octets de la clef longue : ");
        byte[] clef_longue = new byte[LG_FLUX];
        for(int k=0; k < LG_FLUX; k++){
           // System.out.printf("0x%02X", production());
            clef_longue[k] = production();
        }
        System.out.println("\n");

        byte[] f = parseFile("Fabrique de clefs symétriques longues/RC4/Java/src/butokuden.jpg");
        byte[] newF = new byte[f.length];
        System.out.println(f.length);
        for(int i=0; i < f.length; i++){
            int xor = f[i] ^ clef_longue[i];
            newF[i] = (byte) xor;
            
        }
        /*
        for(int i=0; i < newF.length; i++){
            System.out.printf(newF[i]+" ");
        }
        */

        byteToFile("conf.jpg", newF);
        byte[] resume = Resume.md5("conf.jpg");

        // chiffrement du fichier conf.jpg 
        byte[] conf = parseFile("conf.jpg");
        byte[] newConf = new byte[conf.length];
        for(int i=0; i < conf.length; i++){
            int xor = conf[i] ^ clef_longue[i];
            newConf[i] = (byte) xor;     
        }

        byteToFile("newButokuden.jpg", newConf);



        

    }

    private static void echange(int k, int l){
        byte temp = state[k];
        state[k] = state[l];
        state[l] = temp;
    }

    private static void initialisation(){
        int lg = clef.length;
        System.out.println("clef courte utilisée");
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
        System.out.print("la clé "+key+" en ASCII = ");
        for(int i=0; i<key.length(); i++){
            System.out.print(k[i]+" ");
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
