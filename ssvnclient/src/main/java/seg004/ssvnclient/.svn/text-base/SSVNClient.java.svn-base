/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package seg004.ssvnclient;


import java.io.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import seg004.ssvnserver.Message;
import seg004.utils.Utils;

/**
 *
 * @author silvana
 * -Djavax.net.ssl.trustStore=truststore.jks -Djavax.net.ssl.trustStorePassword=secret
 */
public final class SSVNClient {

    private static ObjectOutputStream outputStream;
    private static ObjectInputStream inputStream;
    private static Socket socket;
    private static Scanner in;
    private static String input;
    private static boolean connected = false;
    private static String ip;
    private static int porto;
    // Diffie-Hellman
    private static BigInteger myP, myG;
    private static int myL;
    private static byte[] myBytes;
    private static KeyStore trustStore;
    private static Signature sig;
    private static Cipher outputCipher;
    private static Cipher inputCipher;
    private static Mac mac;

    public static void main(String[] args) throws ClassNotFoundException {
        if (args.length != 2) {
            System.err.println("Argumentos invalidos!");
            return;
        }

        ip = args[0];
        porto = Integer.parseInt(args[1]);

        in = new Scanner(System.in);

        boolean ok = true;

        try {
            SocketFactory socketfactory = (SocketFactory) SocketFactory.getDefault();
            socket = (Socket) socketfactory.createSocket(ip, porto);
            //socket = new Socket(ip, porto);
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
            
            System.out.println("ssvn> A autenticar o servidor...");
            authenticateServer(); // Autenticar o servidor
            System.out.println("ssvn> A estabelecer ligacao segura...");
            diffieHellman(); // Estabelecer segredo partilhado

            do {
                System.out.print("ssvn> ");
                input = in.nextLine();
                String[] cmd = input.split(" ");
                if (input.contains("login") && cmd.length == 3) {
                    System.out.println("ssvn> A fazer login...");
                    login(cmd[1], cmd[2]);
                } else if (input.contains("logout") && cmd.length == 1) {
                    logout();
                    connected = false;
                } else if (input.contains("create") && cmd.length == 2) {
                    create(cmd[1]);
                } else if (input.contains("destroy") && cmd.length == 2) {
                    destroy(cmd[1]);
                } else if (input.contains("adduser") && cmd.length == 4) {
                    adduser(cmd[1], cmd[2], cmd[3]);
                } else if (input.contains("rmvuser") && cmd.length == 3) {
                    rmvuser(cmd[1], cmd[2]);
                } else if (input.contains("list")) {
                    if (cmd.length == 4 && cmd[2].equals("files") && cmd[3].equals("all")) {
                        list(cmd[1], null, true);
                    } else if (cmd.length == 3 && cmd[2].equals("files")) {
                        list(cmd[1], null, false);
                    } else if (cmd.length == 4 && cmd[3].equals("versions")) {
                        list(cmd[1], cmd[2], false);
                    }
                } else if (input.contains("get") && cmd.length > 2) {
                    if (cmd.length > 3) {
                        get(cmd[1], cmd[2], Integer.valueOf(cmd[3]));
                    } else {
                        get(cmd[1], cmd[2], 0);
                    }
                } else if (input.contains("put") && cmd.length > 2) {
                    if (cmd.length > 3) {
                        String comments = new String(cmd[3]);
                        for(int a = 4; a < cmd.length; a++) {
                            comments = new String(comments + " " + cmd[a]);
                        }
                        put(cmd[1], cmd[2], comments);
                    } else {
                        put(cmd[1], cmd[2], null);
                    }
                } else if (input.contains("del") && cmd.length == 3) {
                    del(cmd[1], cmd[2]);
                } else if (input.contains("quit")) {
                    ok = false;
                } else {
                    System.out.println("ssvn> Erro. Comando invalido.");
                }
            } while (ok);
            
            outputStream.close();
            inputStream.close();
            socket.close();
        } catch (UnknownHostException e) {
            System.err.println("Servidor nao foi encontrado!");
        } catch (IOException e) {
            System.err.println("Houve um erro com a ligacao ao servidor!");
            e.printStackTrace();
        }
    }
    
    private static void authenticateServer() {
        try {
            // Enviar o desafio ao servidor...
            SecureRandom sr = new SecureRandom();
            byte[] challenge = new byte[1024 / 16];
            sr.nextBytes(challenge);
            //System.out.println("A enviar o desafio: " + challenge);
            outputStream.writeObject(challenge);

            //System.out.println("A inicializar o motor de cifra");
            FileInputStream ksIn = new FileInputStream(System.getProperty("javax.net.ssl.trustStore"));
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(ksIn, System.getProperty("javax.net.ssl.trustStorePassword").toCharArray());
            java.security.cert.Certificate cert = trustStore.getCertificate("ssvnserver");

            sig = Signature.getInstance("MD5WithRSA");
            sig.initVerify(cert.getPublicKey());
            
            // Receber resposta do servidor
            byte[] signed = (byte[]) inputStream.readObject();
            //System.out.println("Recebi: " + signed);
            sig.update(challenge);
            
            if (!sig.verify(signed)) {
                System.out.println("ssvn> Servidor nao esta' autenticado! A fechar terminar a execucao.");
                System.exit(-1);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void diffieHellman() {
        try {
            
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();
            
            Class dhClass = Class.forName("javax.crypto.spec.DHParameterSpec");
            DHParameterSpec dhSpec = ((DHPublicKey) kp.getPublic()).getParams();
            
            myG = dhSpec.getG();
            myP = dhSpec.getP();
            myL = dhSpec.getL();
            //System.out.println(myG);
            outputStream.writeObject(myG);
            outputStream.writeObject(myP);
            outputStream.writeObject(myL);
            byte[] pub = kp.getPublic().getEncoded();
            
            FileWriter fw = new FileWriter(new File("alice"));
            fw.write(new String(pub));
            fw.close();
            
            outputStream.writeObject(kp.getPublic().getEncoded());
            byte[] bob = (byte[])inputStream.readObject();
            
            fw = new FileWriter(new File("bob"));
            fw.write(new String(bob));
            fw.close();
            
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kp.getPrivate());
            
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec xSpec = new X509EncodedKeySpec(bob);
            PublicKey pk = kf.generatePublic(xSpec);
            ka.doPhase(pk, true);
            
            byte[] secret = ka.generateSecret();
            // Chave AES tem q ser gerada com segredo de 128 bits (16 bytes)
            // Então fazemos hash do segredo partilhado (128 bytes) -> 16 bytes
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(secret);
            byte[] hashedSecret = md.digest();
            SecretKeySpec key = new SecretKeySpec(hashedSecret, "AES");
            
            // Gerar a chave para MAC -> HmacSHA1
            mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec macKey = new SecretKeySpec(secret, "HmacSHA1");
            mac.init(macKey);
            
            // Initialization Vector para CBC
            byte[] iv ={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            outputCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            outputCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            inputCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            inputCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean login(String user, String pass ) throws IOException, ClassNotFoundException{
        if(connected) {
            System.out.println("Utilizador ja' autenticado...");
            return true;
        }
        Message message = new Message();
        message.setType(Message.LOGIN);
        message.setUser(user);
        message.setPass(pass);
        
        if((Boolean)sendAndReceive(message)) {
            connected = true;
            System.out.println("ssvn> Autenticacao concluida com exito");
        } else {
            System.out.println("ssvn> Erro na autenticacao");
        }
           
        return connected;
    }
    
    public static void logout() throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.LOGOUT);
            if((Boolean) sendAndReceive(message)){
                    System.out.println("ssvn> Logout concluido com exito");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static void create(String project) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.CREATE);
            message.setProject(project);
            if((Boolean)sendAndReceive(message)) {
                
            } else {
                System.out.println("ssvn> Erro a criar o projecto.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static void destroy(String project) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.DESTROY);
            message.setProject(project);
            if((Boolean)sendAndReceive(message)) {
                System.out.println("ssvn> Projecto apagado com exito.");
            } else {
                System.out.println("ssvn> Erro ao apagar o projecto.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static void adduser(String project, String userToAdd, String permission) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(4);
            message.setProject(project);
            message.setUserToAdd(userToAdd);
            message.setPermission(permission);
            if((Boolean)sendAndReceive(message)) {
                System.out.println("ssvn> Utilizador adicionado com exito.");
            } else {
                System.out.println("ssvn> Erro ao adicionar o utilizador.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static void rmvuser(String project, String user) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(5);
            message.setProject(project);
            message.setUserToAdd(user);
            if((Boolean)sendAndReceive(message)) {
                System.out.println("ssvn> Utilizador removido com exito.");
            } else {
                System.out.println("ssvn> Erro ao remover o utilizador.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static void list(String project, String file, boolean all) throws IOException, ClassNotFoundException{

        if(connected){
            Message message = new Message();
            message.setType(Message.LIST);
            message.setProject(project);
            if(file != null){
                message.setFile(file);
            } else {
                message.setAll(all);
            }
            // Ler os conteudos do list  
   
            Message ret = (Message)sendAndReceive(message);
            if(ret.getType() == Message.LIST + 100 && ret.getData() != null) {
                String[] result = (String[])ret.getData();
                System.out.println("ssvn> *** List ***");
                for(int i = 0; i < result.length; i++) {
                    System.out.println("ssvn> " + result[i]);
                }
                System.out.println("ssvn> ************");
            } else {
                System.err.println("ssvn> Erro na recepção dos dados.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
        
    
    public static void get(String project, String file, int version) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.GET);
            message.setProject(project);
            message.setFile(file);
            message.setVersion(version);
            // Escrever o ficheiro
            Message ret = (Message)sendAndReceive(message);
            if(ret.getType() == Message.GET + 100 && ret.getData() != null) {
                File fileToWrite = new File(System.getProperty("user.home") + "/" + file);
                if(!fileToWrite.exists())
                    fileToWrite.createNewFile();
                //FileOutputStream fos = new FileOutputStream(fileToWrite);
                //ObjectOutputStream oos = new ObjectOutputStream(fos);
                FileWriter fw = new FileWriter(fileToWrite);
                //System.out.println("A escrever: " + new String((byte[])ret.getData()));
                //oos.writeObject(new String((byte[])ret.getData(), "UTF-8"));
                fw.write(new String((byte[])ret.getData()));
                fw.close();
                //oos.close();
                //fos.close();
                System.out.println("ssvn> Ficheiro recuperado: " + fileToWrite.getAbsolutePath());
            } else {
                System.out.println("ssvn> Ficheiro nao existente ou nao tem permissoes.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
        
    
    public static void put(String project, String fileName, String comment) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.PUT);
            
            File file = new File(fileName);
            if (!file.exists()) {
                System.out.println("ssvn> Ficheiro nao existente.");
                return;
            }
            try {
                FileInputStream fis = new FileInputStream(file);
                byte[] bytes = new byte[(int) file.length()];
                fis.read(bytes);
                fis.close();
                message.setData(bytes);
            } catch (IOException e) {
                System.err.println("ssvn> Erro na leitura do ficheiro.");
                return;
            }
            if(comment != null ){
                message.setProject(project);
                message.setFile(file.getName());
                message.setComment(comment);
            }
            else{
                message.setProject(project);
                message.setFile(file.getName());
            }
      
            if((Boolean)sendAndReceive(message)){
                System.out.println("ssvn> Ficheiro adicionado com exito.");
            } else {
                System.out.println("ssvn> Erro ao adicionar o ficheiro. Pode nao ter permissoes.");
            }
        }   
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
            return;
        }
    }
    public static void del(String project, String file) throws IOException, ClassNotFoundException{
        if(connected){
            Message message = new Message();
            message.setType(Message.DEL);
            message.setProject(project);
            message.setFile(file);
            if((Boolean) sendAndReceive(message)) {
                System.out.println("ssvn> Ficheiro apagado com exito.");
            } else {
                System.out.println("ssvn> Erro ao apagar o ficheiro. Pode nao ter permissoes.");
            }
        }
        else{
            System.out.println("ssvn> Utilizador tem que estar autenticado");
        }
    }
    
    public static Object sendAndReceive(Message message) {
        try {
            byte[] cipheredMessage = outputCipher.doFinal(Utils.serialize(message));
            byte[] cipheredMac = mac.doFinal(cipheredMessage);
            // Enviar a mensagem
            outputStream.writeObject(cipheredMessage);
            outputStream.writeObject(cipheredMac);
            
            // Receber a resposta do servidor
            byte[] reply = (byte[])inputStream.readObject();
            byte[] replyMac = (byte[])inputStream.readObject();
            if(Arrays.equals(replyMac, mac.doFinal(reply))) {
                Object ret = Utils.deserialize(inputCipher.doFinal(reply));
                return ret;
            } else {
                System.err.println("Erro na recepcao da resposta do servidor!");
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}