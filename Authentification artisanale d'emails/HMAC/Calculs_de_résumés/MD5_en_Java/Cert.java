import java.io.*;
import java.nio.file.Path;
import java.security.*;
import java.util.*;

public class Cert {

    public static List<String> parseFile(String filename) throws Exception{
        List<String> lines = new ArrayList<>();
        String line;
        try{
            BufferedReader br = new BufferedReader(new FileReader(filename));
            while((line = br.readLine()) != null){
                //System.out.print(line);
                lines.add(line);
            }                
            //lines.add(" ");
            //System.out.println(lines);
        }catch(IOException e){
            e.printStackTrace();
        }

        return lines;
    }



    public static byte[] md5(String s) throws Exception {

        MessageDigest hacheur = MessageDigest.getInstance("MD5");

        s+="\r";
        //System.out.print(s);
        byte[] buff = s.getBytes();
        hacheur.update(buff);
        byte[] r = hacheur.digest();  
        return r ;

    }

    public static String extractBody(List<String> lines){
        String body="";
        for(String s : lines){
            if(s.isEmpty()){
               for(int i=lines.indexOf(s)+1; i<lines.size(); i++){
                   if(i==lines.size()-1){
                    body += lines.get(i);
                    break;
                   }
                   else{
                     body += lines.get(i)+"\r\n";
                    }

               }
               break;
            }
        }
        return body;
        
    }

    public static String extractHeader(List<String> lines){
        String header="";
        for(String s : lines){
            if(!s.isEmpty()){
               header += s+"\n";
            }else{
                break;
            }
        }
        return header;
        
    }

    public static File constructFile(String body, String secret) throws Exception{

        File file = new File("corps_avec_secret_programme.txt");
        if(!file.exists()){
            file.createNewFile();
        }
        PrintWriter writer = new PrintWriter(file);
        writer.print(body);
        writer.print("\r\n"+secret);
        writer.close();
        System.out.println("le fichier prog a été crée");
        return file;

    }

    public static void insertField(String filename) throws Exception{
        List<String> lines = parseFile(filename);
        String header = extractHeader(lines);
        String body = extractBody(lines);
        String secret = "c5dcb78732e1f3966647655229729843";
    
        byte[] r = Resume.md5(constructFile(body, secret).getName());
        StringBuilder xAuth = new StringBuilder("X-AUTH: ");
        System.out.println();
        for(byte k: r){
            System.out.printf("%02x", k);
            xAuth.append(String.format("%02x", k));
        }    
        System.out.println();
        //System.out.println(xAuth.toString());
    
        header +=xAuth.toString()+"\n";


        File file = new File("email1-authTest.txt");
        if(!file.exists()){
            file.createNewFile();
        }
        PrintWriter writer = new PrintWriter(file);
        writer.println(header);
        writer.print(body);
        writer.close();
        System.out.println("le fichier a été crée");


        
    }
    


    public static void main(String[] args) throws Exception{
        //parseFile(args[0]);
        insertField(args[0]);

        



             
    }


    
}
