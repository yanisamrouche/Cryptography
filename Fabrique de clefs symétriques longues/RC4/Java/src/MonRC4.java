public class MonRC4 {
    private static int LG_FLUX =10;
    static byte[] clef = {(byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5};

    //Etat interne de RC4
    static byte[] state = new byte[256];
    static int i=0, j=0;

    public static void main(String[] args){
        initialisation();
        System.out.println("Premiers octets de la clef longue : ");
        for(int k=0; k < LG_FLUX; k++){
            System.out.printf("0x%02X", production());
        }
        System.out.println("\n");
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
}
