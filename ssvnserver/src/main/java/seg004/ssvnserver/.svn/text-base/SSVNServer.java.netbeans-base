/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package seg004.ssvnserver;

import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.naming.NamingException;
import seg004.ssvn.SSVN;
import seg004.utils.Utils;
import sun.misc.BASE64Encoder;

/**
 *
 * @author vasco 
 * -Djavax.net.ssl.keyStore=ssvnserver.ks
 */
public final class SSVNServer {
    /**
     * Main - Liga:
     *  Serviço SSVN
     *  Serviço LDAP
     * 
     * Fica à espera de ligações e cria uma thread por ligação.
     * 
     * @author vasco
     */
    private static int serverPort = -1;
    private ServerSocket serverSocket = null;
    private String serverPassword = null;
    
    public static void main(String[] args) {
        if(args.length != 1) {
            System.out.println("Argumentos incorrectos: ./SSVNServer <port>");
            return;
        }
        Console console;
        char[] password;
        if((console = System.console()) != null &&
             (password = console.readPassword("%s", "Server Password: ")) != null) {
            try {             
                System.setProperty("javax.net.ssl.keyStorePassword", new String(password));
                System.setProperty("javax.net.ssl.trustStorePassword", new String(password));
                
                // Testar password...´
                FileInputStream ksIn = new FileInputStream(System.getProperty("javax.net.ssl.keyStore"));
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(ksIn, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());
                
                byte[] passwordBytes = new String(password).getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] hashedPassword = md.digest(passwordBytes); // HashedSecret tem 16 bytes
                System.out.println(passwordBytes.length + " " + hashedPassword.length);

                /*SecretKeySpec key = new SecretKeySpec(hashedPassword, "AES");
                Cipher encrypt = Cipher.getInstance("AES");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
                Cipher decrypt = Cipher.getInstance("AES");
                decrypt.init(Cipher.DECRYPT_MODE, key);

                Mac mac = Mac.getInstance("HmacSHA1");
                SecretKeySpec macKey = new SecretKeySpec(hashedPassword, "HmacSHA1");
                mac.init(macKey);*/

                serverPort = Integer.parseInt(args[0]);

                // Inicializar o SSVN, vai ser um objecto Singleton.
                // Novo: SSVN.init(Mac, Cipher);
                System.out.println("A ligar o SSVN");
                SSVN.init(hashedPassword);

                SSVNServer server = new SSVNServer();
                server.initServer(new String(password));
            } catch (Exception e) {
                System.err.println("** ERRO COM PASSWORD OU VARIAVEIS DE AMBIENTE **");
                e.printStackTrace();
            }
        } else {
            System.out.println("Erro na leitura da password.");
        }
    }
    
    private void initServer(String password) {
        this.serverSocket = null;
        try {
            this.serverSocket = new ServerSocket();
            this.serverSocket.setReuseAddress(true);
            this.serverSocket.bind(new InetSocketAddress(serverPort));
            this.serverPassword = password;
        }
        catch(IOException e) {
            System.err.println("Erro na inicializacao do servidor!");
            System.err.println(serverPort);
            e.printStackTrace();
            System.exit(-1);
        }
        
        // Correu tudo bem ate' aqui... Vamos entao ficar a espera de ligações...
        System.out.println("Servidor inicializado... A' espera de ligacoes...");
        Thread hook = new ShutdownHook();
        Runtime.getRuntime().addShutdownHook(hook);
        
        while(true) {
            try {
                Socket client = this.serverSocket.accept();
                // Criar um novo thread para lidar com este pedido
                System.out.println("Recebi uma nova ligacao!");
                HandlerThread thread = new HandlerThread(client, this.serverPassword);
                thread.start();
            }
            catch(IOException e) {
                System.err.println("Erro na ligacao com um cliente...");
                e.printStackTrace();
                break;
            }
        }
    }
    
    private class ShutdownHook extends Thread {     
        @Override
        public void run() {
            try {
                System.out.println("A terminar o servidor!");
                serverSocket.close();
            }
            catch(IOException e) {
                
            }
        }
    }
    
    private class HandlerThread extends Thread {
        // Cada thead do servidor precisa de:
        // Uma socket de ligação
        private Socket threadSocket = null;
        // Uma stream de saida
        private ObjectOutputStream threadOutputStream = null;
        // Uma stream de entrada
        private ObjectInputStream threadInputStream = null;
        // Cifras de entrada/saida
        private Cipher outputCipher = null;
        private Cipher inputCipher = null;
        private Signature sig = null;
        private Mac mac = null;
        private String user = null;
        private String serverPassword = null;
        
        private HandlerThread(Socket threadSocket, String serverPassword) {
            this.threadSocket = threadSocket;
            
            // Criar as input/output streams
            try {
                this.threadOutputStream = new ObjectOutputStream(threadSocket.getOutputStream());
                this.threadInputStream = new ObjectInputStream(threadSocket.getInputStream());
                this.serverPassword = serverPassword;
            }
            catch(Exception e) {
                System.err.println("Erro na criação dos streams da thread...");
                e.printStackTrace();
            }
            System.out.println("Ligação efectuada com sucesso.");
        }
        
        private void doChallenge() {
            try {
                // Receber desafio do cliente...
                byte[] challenge = (byte[]) this.threadInputStream.readObject();
                System.out.println("1. Recebi o desafio: " + new String(challenge));
                KeyStore keyStore;

                System.out.println("2. A inicializar o motor de cifra " + System.getProperty("javax.net.ssl.keyStore"));
                FileInputStream ksIn = new FileInputStream(System.getProperty("javax.net.ssl.keyStore"));
                keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(ksIn, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());

                sig = Signature.getInstance("MD5WithRSA");
                sig.initSign((PrivateKey) keyStore.getKey("ssvnserver", System.getProperty("javax.net.ssl.keyStorePassword").toCharArray()));

                sig.update(challenge);
                byte[] signed = sig.sign();

                // Enviar desafio cifrado ao cliente...
                System.out.println("3. A enviar os dados assinados com a chave privada...");
                this.threadOutputStream.writeObject(signed);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void diffieHellman() {
            try {
                BigInteger aliceG = (BigInteger) this.threadInputStream.readObject();
                BigInteger aliceP = (BigInteger) this.threadInputStream.readObject();
                Integer aliceL = (Integer) this.threadInputStream.readObject();
                DHParameterSpec dhSpec = new DHParameterSpec(aliceP, aliceG, aliceL);

                byte[] alice = (byte[]) this.threadInputStream.readObject();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                KeyFactory bKFFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alice);
                PublicKey aPK = bKFFac.generatePublic(x509KeySpec);
                //DHParameterSpec dhParamSpec = ((DHPublicKey) aPK).getParams();
                kpg.initialize(dhSpec);
                KeyPair kp = kpg.generateKeyPair();

                this.threadOutputStream.writeObject(kp.getPublic().getEncoded());

                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(kp.getPrivate());

                KeyFactory kf = KeyFactory.getInstance("DH");
                X509EncodedKeySpec xSpec = new X509EncodedKeySpec(alice);
                PublicKey pk = kf.generatePublic(xSpec);
                ka.doPhase(pk, true);

                byte[] secret = ka.generateSecret();
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] hashedSecret = md.digest(secret);
                SecretKeySpec key = new SecretKeySpec(hashedSecret, "AES");
                
                // Initialization Vector para 
                byte[] iv ={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                // Gerar a chave para MAC -> HmacSHA1
                mac = Mac.getInstance("HmacSHA1");
                SecretKeySpec macKey = new SecretKeySpec(secret, "HmacSHA1");
                mac.init(macKey);

                inputCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                inputCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                outputCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                outputCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        private boolean authenticate() throws InterruptedException {
            String userPass[] = new String[2];
            Message message;
            boolean loginOK = false;
            int loginAttempts = 0;
            do {
                try {
                    //userPass[0] = (String) this.threadInputStream.readObject();
                    //userPass[1] = (String) this.threadInputStream.readObject();
                    System.out.println("A' espera de credenciais de login...");
                    message = this.recv();
                    userPass[0] = message.getUser();
                    
                    MessageDigest md = MessageDigest.getInstance("SHA-1");
                    BASE64Encoder b64e = new BASE64Encoder();
                    userPass[1] = new String("{SHA}" + b64e.encode(md.digest(message.getPass().getBytes("UTF-8"))));
                    
                    //System.out.println("User: " + userPass[0] + ", Pass: " + userPass[1]);

                    if (Ldap.autentica("cn=" + userPass[0] + ",o=seg", userPass[1])) {
                        this.send(new Boolean(true));
                        this.user = message.getUser();
                        loginOK = true;
                    }
                } catch(NamingException e) {
                    e.printStackTrace();
                    // User/Pass não existente... Sleep!
                    sleep(1000 * loginAttempts);
                    this.send(new Boolean(false));
                    loginAttempts++;
                    System.err.println("Login invalido... A esperar um pouco...");
                } catch(Exception e) {
                    e.printStackTrace();
                    return false;
                }
            } while (!loginOK && loginAttempts < 3);
            
            return loginOK;
        }

        private Message validateAndDecipher(byte[] msg, byte[] mac) {
            byte[] msgMac = this.mac.doFinal(msg);
            if (Arrays.equals(msgMac, mac)) {
                try {
                    Message message = (Message) Utils.deserialize(this.inputCipher.doFinal(msg));
                    return message;
                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                }
            } else {
                System.err.println("MAC Invalido! A fechar a ligação...");
                return null;
            }
        }

        private void send(Object objectToSend) {
            try {
                byte[] cipheredObject = this.outputCipher.doFinal(Utils.serialize(objectToSend));
                byte[] cipheredMac = this.mac.doFinal(cipheredObject);
                this.threadOutputStream.writeObject(cipheredObject);
                this.threadOutputStream.writeObject(cipheredMac);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private Message recv() {
            Message message = null;
            try {
                byte[] ciphered = (byte[]) this.threadInputStream.readObject();
                byte[] mac = (byte[]) this.threadInputStream.readObject();
                message = validateAndDecipher(ciphered, mac);
                if (message == null) {
                    System.err.println("Erro na verificação do MAC! A encerrar esta ligação...");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return message;
        }

        @Override
        public void run() {
            int loginAttempts = 0;
            String user = "";
            Message newMessage, message;

            // Estabelecer ligação segura.
            doChallenge();
            diffieHellman();

            try {
                if (this.authenticate()) {
                    boolean running = true, ret;
                    while (running) {
                        System.out.println("A espera de pedidos do cliente autenticado...");
                        // Receber a mensagem...
                        message = recv();
                        if (message != null) {
                            //Message message = (Message) this.threadInputStream.readObject(), newMessage;
                            System.out.println("Mensagem com tipo " + message.getType());
                            switch (message.getType()) {
                                case Message.ADDUSER:
                                    System.out.println("A adicionar " + message.getUserToAdd() + " ao projecto " + message.getProject());
                                    ret = SSVN.addUser(message.getProject(), this.user, message.getUserToAdd(), message.getPermission());
                                    System.out.println(Boolean.toString(ret));
                                    this.send(new Boolean(ret));
                                    break;
                                case Message.CREATE:
                                    System.out.println("A criar um novo projecto para " + this.user);
                                    ret = SSVN.createProject(message.getProject(), this.user);
                                    this.send(new Boolean(ret));
                                    break;
                                case Message.DEL:
                                    System.out.println("A apagar o ficheiro " + message.getFile() + " do projecto " + message.getProject());
                                    ret = SSVN.del(message.getProject(), this.user, message.getFile(), message.getComment());
                                    this.send(new Boolean(ret));
                                    break;
                                case Message.DESTROY:
                                    System.out.println("A destruir o projecto " + message.getProject());
                                    ret = SSVN.destroy(message.getProject(), this.user);
                                    this.send(new Boolean(ret));
                                    break;
                                case Message.GET:
                                    System.out.println("A fazer get de " + message.getFile() + " do projecto " + message.getProject());
                                    byte[] fileToReturn = SSVN.get(message.getProject(), this.user, message.getFile(), message.getVersion());
                                    if(fileToReturn == null) {
                                        System.out.println("Ooops o ficheiro nao foi recuperado!");
                                    }
                                    newMessage = new Message();
                                    newMessage.setData(fileToReturn);
                                    newMessage.setType(Message.GET + 100);
                                    this.send(newMessage);
                                    break;
                                case Message.LIST:
                                    System.out.println("A fazer list...");
                                    String[] stringToReturn;
                                    newMessage = new Message();
                                    if (message.getFile() != null) {
                                        // List file
                                        System.out.println("List file...");
                                        stringToReturn = SSVN.listFiles(message.getProject(), this.user, message.getFile());
                                    } else {
                                        // List project
                                        System.out.println("List project...");
                                        stringToReturn = SSVN.listProject(message.getProject(), this.user, message.getAll());
                                    }
                                    newMessage.setType(Message.LIST + 100);
                                    newMessage.setData(stringToReturn);
                                    this.send(newMessage);
                                    break;
                                case Message.LOGOUT:
                                    System.out.println("Cliente fez logout, já nao esta autenticado.");
                                    this.send(new Boolean(true));
                                    this.user = null;
                                    running = this.authenticate();
                                    break;
                                case Message.PUT:
                                    System.out.println("A inserir um novo ficheiro.");
                                    ret = SSVN.put(message.getProject(), this.user, message.getFile(), (byte[]) message.getData());
                                    this.send(new Boolean(ret));
                                    break;
                                case Message.RMVUSER:
                                    System.out.println("A remover " + message.getUserToAdd() + " do projecto " + message.getProject());
                                    ret = SSVN.removeUser(message.getProject(), this.user, message.getUserToAdd());
                                    this.send(new Boolean(ret));
                                    break;
                                default:
                                    break;
                            }
                        } else {
                            System.err.println("Erro na recepcao da mensagem! A terminar esta ligacao!");
                            running = false;
                        }
                    }
                }
                System.out.println("A fechar uma ligacao...");
                this.threadSocket.close();
            } catch(EOFException e) {
                System.out.println("Ligacao fechada");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
