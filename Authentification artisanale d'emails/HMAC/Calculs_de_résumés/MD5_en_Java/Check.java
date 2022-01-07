import java.util.List;

public class Check {

    public static boolean checkAuth(String filename) throws Exception{

        List<String> lines = Cert.parseFile(filename);
        String body = Cert.extractBody(lines);
        String authField = "";
        for(String s : lines){
            if(s.contains("X-AUTH:")){
                authField += s;
                break;
            }
        }
        String h = authField.substring(8);
        byte[] h_body_bytes = Cert.md5(body+"c5dcb78732e1f3966647655229729843");
        StringBuilder h_body = new StringBuilder();
        for(byte b : h_body_bytes){
            h_body.append(String.format("%02x", b));
        }
        String h_ = h_body.toString();

        if(!h.equals(h_)){
            System.out.println("Alerte : le message est frauduleux !");
            return false;
        }
        System.out.println("l'email est authentique");
        return true;
    }

    public static void main(String[] args) throws Exception{
        checkAuth(args[0]);
        
    }
    
}
