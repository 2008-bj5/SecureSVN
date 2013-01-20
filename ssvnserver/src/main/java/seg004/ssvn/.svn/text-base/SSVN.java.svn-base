/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package seg004.ssvn;

import java.io.*;
import java.util.*;
import javax.naming.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import seg004.ssvnserver.Ldap;
import seg004.ssvn.User;
import seg004.ssvn.Header;
import seg004.ssvn.Cifra;
import seg004.ssvn.MacGenerator;
import seg004.utils.Utils;

/**
 *
 * @author vasco
 */
public class SSVN {

    private static final Lock lock = new ReentrantLock();
    private static SSVN ssvn = null;
    
    /*public static void main(String[] args) {
        init();
        //me.addFile("myProject", "vasco", "aFile", "haha", null);
        //me.addFile("myProject", "vasco", "another", "hehe", null);
        //System.out.println(me.listAllFileVersions("myProject", "aFile", "vasco")[0]);
        String[] res = SSVN.listProject(new String("vasco"), new String("vasco"), false);
        for(int i = 0; i < res.length; i++) {
            System.out.println(res[i]);
        }
    }*/
    
    private static void destroyDirectory(File dir) {
        if(!dir.exists())
            return;
        
        File[] files = dir.listFiles();
        Arrays.sort(files);
        
        for(int i = 0; i < files.length; i++) {
            // para cada ficheiro na directoria a destruir ou apaga se é ficheiro
            if(files[i].exists() && !files[i].isDirectory()) {
                System.out.println("A apagar " + files[i].toString());
                files[i].delete();
            } else if(files[i].isDirectory()) {
                // Ou então, se é directoria verifica se tem ficheiros
                if(files[i].listFiles().length == 0) {
                    // Se não tiver ficheiros apaga a directoria
                    System.out.println("A apagar " + files[i].toString());
                    files[i].delete();
                } else {
                    // Se nao volta a correr recursivamente sobre essa directoria
                    System.out.println("Dir nao vazia: " + files[i].toString());
                    destroyDirectory(files[i]);
                }
            }
        }
        
        dir.delete();
    }
    
    public static void init(byte[] key) {
        if(ssvn == null) {
            ssvn = new SSVN(key);
        }
    }
    
    public static boolean validPermissions(String permissions) {
        return permissions.equals("rw") || permissions.equals("ow") || permissions.equals("ro");
    }
    
    public static boolean createProject(String projectName, String userName) {
        boolean ret;
        try {
            lock.lock();
            // Zona critica: criar um novo projecto.
            ret = ssvn.create(projectName, userName);
        }
        finally {
            lock.unlock();
        }   
        return ret;
    }
    
    public static boolean addUser(String projectName, String userAdding, String userToAdd, String permissions) {
        lock.lock();
        boolean ret = ssvn.addUserWithPermissions(projectName, userAdding, userToAdd, permissions);
        lock.unlock();
        return ret;
    }
    
    public static boolean removeUser(String projectName, String userRemoving, String userToRemove) {
        lock.lock();
        boolean ret = ssvn.removeUserFromProject(projectName, userRemoving, userToRemove);
        lock.unlock();
        return ret;
    }
    
    public static boolean put(String projectName, String userName, String fileName, byte[] file) {
        lock.lock();
        boolean ret = ssvn.addFile(projectName, userName, fileName, fileName, file);
        lock.unlock();
        return ret;
    }
    
    public static String[] listProject(String projectName, String userName, boolean all) {
        lock.lock();
        String[] ret = ssvn.listAllProjectFiles(projectName, userName, all);
        lock.unlock();
        return ret;
    }
    
    public static boolean del(String projectName, String userName, String fileName, String comments) {
        lock.lock();
        boolean ret = ssvn.addFile(projectName, userName, fileName, comments, null);
        lock.unlock();
        return ret;
    }
    
    public static String[] listFiles(String projectName, String userName, String fileName) {
        lock.lock();
        String[] ret = ssvn.listAllFileVersions(projectName, userName, fileName);
        lock.unlock();
        return ret;
    }
    
    public static byte[] get(String projectName, String userName, String fileName, int version) {
        lock.lock();
        byte[] ret = ssvn.getProjectFile(projectName, userName, fileName, version);
        lock.unlock();
        return ret;
    }
    
    public static boolean destroy(String projectName, String userName) {
        lock.lock();
        boolean ret = ssvn.destroyProject(projectName, userName);
        lock.unlock();
        return ret;
    }
    
    private String ssvnDir = new String(System.getProperty("user.home") + "/ssvn/repository/");
    private HashMap<String, ArrayList<String>> projectsAndUsers = new HashMap<String, ArrayList<String>> ();
    private HashMap<String, String> projectsAndOwners = new HashMap<String, String> ();
    private Cifra cifra;
    private MacGenerator mac;
    
    private SSVN(byte[] key) {
        File dir = new File(this.ssvnDir);
        
        this.cifra = new Cifra(key);
        this.mac = new MacGenerator(key);
        
        // Se não existe então isto é a primeira execução...
        if(!dir.exists()) {
            dir.mkdirs();
        } else {
            // Caso contrario vamos ver o conteudo e propagar os hashMaps dos projectos !
            File dirs[] = dir.listFiles();
            Arrays.sort(dirs);
            
            for(int i = 0; i < dirs.length; i++) {
                if(dirs[i].isDirectory()) {
                    // Encontramos um projecto...
                    System.out.println("Projecto encontrado: " + dirs[i].toString());
                    
                    String usersFileName = new String(dirs[i].toString() + "/users.txt");
                    File usersFile = new File(usersFileName);
                    
                    if(!usersFile.exists()) {
                        System.err.println("Na leitura dos projectos houve um erro.");
                        System.err.println("Pode então o programa não correr como esperado.");
                        System.err.println("No entanto vamos tentar compor as coisas");
                        System.err.println("Ao apagar a directoria " + dirs[i].toString());
                        destroyDirectory(dirs[i]);
                    } else {
                        User user = null;
                        boolean foundOwner = false;
                        ArrayList<String> projectUsers = new ArrayList<String> ();
                        
                        try {
                            //FileInputStream fis = new FileInputStream(usersFile);
                            //ObjectInputStream users = new ObjectInputStream(fis);
                            ArrayList<User> usersList = (ArrayList<User>) this.readFile(usersFile);
                            if (usersList != null) {
                                User[] usersArray = (User[]) usersList.toArray(new User[usersList.size()]);
                                for (int j = 0; j < usersArray.length; j++) {
                                    System.out.println("Utilizador recuperado: " + usersArray[j].name());
                                    //String[] thisUser = user.split(" ");
                                    if (usersArray[j].isOwner()) {
                                        foundOwner = true;
                                        this.projectsAndOwners.put(dirs[i].getName(), usersArray[j].name());
                                    } else if (usersArray[j].isOwner() && foundOwner) {
                                        System.err.println("Na leitura dos projectos houve um erro,");
                                        System.err.println("Pois foram encontrados dois donos onde só devia haver um.");
                                        System.err.println("Pode então o programa não correr como esperado.");
                                        System.err.println("No entanto vamos tentar compor as coisas");
                                        System.err.println("Ao apagar a directoria " + dirs[i].toString());
                                        destroyDirectory(dirs[i]);
                                        foundOwner = false;
                                    }
                                    projectUsers.add(usersArray[j].name());
                                }
                            } else {
                                System.err.println("Nao lemos nada do ficheiro! Houve algum erro...");
                            }
                            
                            if(!foundOwner) {
                                System.err.println("Oops, o projecto " + dirs[i].getName() + " nao tem dono!");
                                destroyDirectory(dirs[i]);
                            }
                        } catch (Exception e) {
                            System.err.println("Erro com projecto: " + dirs[i].getName());
                            destroyDirectory(dirs[i]);
                        }
                        if(foundOwner) {
                            System.out.println("Correu tudo como esperado, vou adicionar os projectos e os seus utilizadores...");
                            this.projectsAndUsers.put(dirs[i].getName(), projectUsers);
                        }
                    }
                }
            }
        }
        System.out.println(projectsAndOwners.toString());
        System.out.println(projectsAndUsers.toString());
    }
    
    private Object readFile(File file) throws FileNotFoundException, IOException, ClassNotFoundException {
        File macFile = new File(new String(file.getAbsolutePath() + ".mac"));
        Object ret = null;
        FileInputStream fis = new FileInputStream(macFile);
        ObjectInputStream ois = new ObjectInputStream(fis);

        byte[] initialMac = (byte[]) ois.readObject();

        fis.close();
        ois.close();
        
        fis = new FileInputStream(file);
        ois = new ObjectInputStream(fis);

        byte[] ciphered = (byte[]) ois.readObject();
        if (mac.comparaMac(initialMac, ciphered)) {
            byte[] deciphered = this.cifra.decifra(ciphered);
            ret = Utils.deserialize(deciphered);
        }
        
        fis.close();
        ois.close();
        
        return ret;
    }
    
    private void writeDataToFileAndCreateMac(byte[] data, File file) throws IOException {
        File macFile = new File(new String(file.getAbsolutePath() + ".mac"));
        if(!macFile.exists()) {
            macFile.createNewFile();
        }
        if(!file.exists()) {
            file.createNewFile();
        }
        
        FileOutputStream fos = new FileOutputStream(file);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        
        FileOutputStream mfos = new FileOutputStream(macFile);
        ObjectOutputStream moos = new ObjectOutputStream(mfos);
        
        byte[] ciphered = this.cifra.cifra(data);
        byte[] cipheredMac = this.mac.geraMac(ciphered);
        
        oos.writeObject(ciphered);
        moos.writeObject(cipheredMac);
        
        moos.close();
        mfos.close();
        oos.close();
        fos.close();
    }
    
    private boolean create(String projectName, String ownerName) {
        String fullName = new String(this.ssvnDir + projectName + "/");
        boolean ret = false;
        // Verifica se ainda não existe esse projecto...
        File newProject = new File(fullName);
        if(!newProject.exists()) {
            newProject.mkdir();
            //ProjectUser owner = new ProjectUser(ownerName, "rw");
            //owner.setIsOwner(true);
            //String userString = new String(ownerName + " rw " + Boolean.toString(true));
            User user = new User(ownerName, "rw", true);
            try {
                File users = new File(newProject.toString() + "/users.txt");
                
                //oos.writeObject(owner);
                ArrayList<User> list = new ArrayList<User>();
                list.add(user);
                
                this.writeDataToFileAndCreateMac(Utils.serialize(list), users);
                this.projectsAndOwners.put(projectName, ownerName);
                ArrayList<String> usersList = new ArrayList<String>();
                usersList.add(ownerName);
                this.projectsAndUsers.put(projectName, usersList);
                ret = true;
            } catch(Exception e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Houve uma tentativa de criar um projecto onde outro já existia");
            System.err.println("Então eu resolvi não permitir que tal coisa acontecesse!");
        }
        return ret;
    }
    
    private boolean destroyProject(String projectName, String userName) {
        String owner = this.projectsAndOwners.get(projectName);
        System.out.println(owner);
        if(owner != null && owner.equals(userName)) {
            File projectDirectory = new File(new String(this.ssvnDir + projectName));
            if(projectDirectory.exists()) {
                destroyDirectory(projectDirectory);
                return true;
            }
            return false;
        } else {
            System.err.println("Houve uma tentativa de destruicao de projecto por alguem que nao era o dono!");
            return false;
        }
    }
    
    private boolean addFile(String projectName, String userName, String fileName, String comments, byte[] file) {
        boolean ret = false, deleted = (file == null);
        int numFiles = 0;
        if(this.projectsAndUsers.containsKey(projectName)) {
            ArrayList<String> users = this.projectsAndUsers.get(projectName);
            //System.out.println(users + " " + userName);
            if(users.contains(userName)) {
                // Vamos abrir o users.txt e verificar as permissoes
                String permissions = this.getPermissions(projectName, userName);
                //System.err.println("permissions: " + permissions);
                if(permissions.equals("rw") || permissions.equals("ow")) {
                    // Projecto existe e utilizador tem permissoes de escrita
                    String directory = this.ssvnDir + projectName + "/" + fileName + "/";
                    File fileDirectory = new File(directory);
                    if(!fileDirectory.exists()) {
                        fileDirectory.mkdir();
                    }
                    if(fileDirectory.list() != null)
                        numFiles = fileDirectory.list().length / 2;
                    numFiles ++;
                    File fileToWrite = new File(directory + fileName + "-" + numFiles);
                    //System.out.println("Creating file " + fileToWrite.toString() + " with contents: " + new String(file));
                    try {
                        Header header = new Header(userName, comments, numFiles, deleted);
                        FileAndHeader toWrite = new FileAndHeader(header, file);
                        this.writeDataToFileAndCreateMac(Utils.serialize(toWrite), fileToWrite);
                        ret = true;
                    }
                    catch(IOException e) {
                        e.printStackTrace();
                    }
                } else {
                    System.err.println("Houve uma tentativa de escrita por um utilizador que nao tinha permissoes para tal! (2)");
                }
            } else {
                System.err.println("Houve uma tentativa de escrita por um utilizador que nao tinha permissoes para tal! (1)");
            }
        }
        return ret;
    }
    
    private String[] listAllProjectFiles(String projectName, String userName, boolean all) {
        String permissions = this.getPermissions(projectName, userName);
        //System.out.println(permissions);
        if(permissions != null && (permissions.equals("rw") || permissions.equals("ro"))) {
            ArrayList<String> projectFiles = new ArrayList<String> ();
            File projectDirectory = new File(new String(this.ssvnDir + projectName + "/"));
            if(!projectDirectory.exists()) {
                return null;
            } else {
                File[] files = projectDirectory.listFiles();
                for(int i = 0; i < files.length; i++) {
                    if(files[i].isDirectory()) {
                        // Verificar se o ficheiro foi apagado...
                        File[] fileVersions = files[i].listFiles();
                        int numVersions = fileVersions.length / 2;
                        boolean deleted = false;
                        for(int j = 0; j < fileVersions.length; j++) {
                            if(fileVersions[j].getAbsolutePath().endsWith(new String("-" + numVersions))) {
                                try {
                                    FileAndHeader contents = (FileAndHeader)this.readFile(fileVersions[j]);
                                    deleted = contents.getHeader().isDeleted();
                                }
                                catch(IOException e) {
                                    e.printStackTrace();
                                } catch(ClassNotFoundException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        if(!deleted)
                            projectFiles.add(files[i].getName());
                        else if(all)
                            projectFiles.add(files[i].getName());
                    }
                }
                return projectFiles.toArray(new String[projectFiles.size()]);
            }
        } else {
            System.err.println("Houve uma tentativa de leitura por alguem que não tinha permissoes.");
            return null;
        }
    }
    
    private String[] listAllFileVersions(String projectName, String userName, String fileName) {
        String permissions = this.getPermissions(projectName, userName);
        //System.out.println(projectName + " " + userName);
        if(permissions != null && (permissions.equals("rw") || permissions.equals("ro"))) {
            ArrayList<String> fileVersions = new ArrayList<String> ();
            File fileDirectory = new File(new String(this.ssvnDir + projectName + "/" + fileName));
            if(!fileDirectory.exists()) {
                return null;
            } else {
                File[] files = fileDirectory.listFiles();
                for(int i = 0; i < files.length; i ++) {
                    try {
                        if(!files[i].getAbsolutePath().endsWith(".mac")) {
                            FileAndHeader contents = (FileAndHeader) this.readFile(files[i]);

                            if (contents != null && contents.getHeader() != null) {
                                Header header = contents.getHeader();
                                fileVersions.add(new String(header.getVersion() + " " + header.getUserName() + " " + header.getComments()));
                            }
                        }
                    } catch(IOException e) {
                        e.printStackTrace();
                    } catch(ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
                return fileVersions.toArray(new String[fileVersions.size()]);
            }
        } else {
            System.err.println("Houve uma tentativa de leitura por alguem que não tinha permissoes.");
            return null;
        }
    }
    
    private byte[] getProjectFile(String projectName, String userName, String fileName, int version) {
        byte[] ret = null;
        String permissions = this.getPermissions(projectName, userName);
        //System.out.println(permissions);
        File theFile = null;
        boolean found = false;
        if(permissions != null && (permissions.equals("rw") || permissions.equals("ro"))) {
            File fileDirectory = new File(new String(this.ssvnDir + projectName + "/" + fileName));
            if(fileDirectory.exists()) {
                File[] files = fileDirectory.listFiles();
                for(int i = 0; i < files.length && !found; i++) {
                    //System.err.println(files[i]);
                    if((version > 0 && files[i].toString().endsWith(new String("-" + version))) ||
                       (version == 0 && files[i].toString().endsWith(new String("-" + (files.length / 2))))) {
                        theFile = files[i];
                        found = true;
                    }
                }
                if(found) {
                    try {
                        FileAndHeader contents = (FileAndHeader)this.readFile(theFile);
                        if(contents != null && contents.getContents() != null) {
                            ret = contents.getContents();
                        }
                    }
                    catch(ClassNotFoundException e) {
                        e.printStackTrace();
                    } catch(IOException e) {
                        e.printStackTrace();
                    }
                } else {
                    System.out.println("O ficheiro nao existe!");
                    return null;
                }
            } else {
                System.err.println("Nao podemos ler o ficheiro que o projecto nao existe!");
                return null;
            }
        } else {
            System.err.println("Houve uma tentativa de leitura por alguem que nao tinha permissoes!");
            System.err.println("Ou o projecto pedido nao existe.");
        }
        return ret;
    }
    
    /*private byte[] getFile(String projectName, String fileName, String userName, int version) {
        
    }*/
    
    private boolean addUserWithPermissions(String projectName, String userAdding, String userToAdd, String permissions) {
        boolean ret = false;
        
        if(this.projectsAndUsers.containsKey(projectName) && validPermissions(permissions)) {
            ArrayList<String> users = this.projectsAndUsers.get(projectName);
            System.out.println("A verificar se e' o dono que esta a adicionar...");
            if(projectsAndOwners.get(projectName).equals(userAdding)) {
                if(users.contains(userToAdd)) {
                    // Vamos apagar este utilizador
                    System.out.println("Temos que remover o utilizador " + userToAdd);
                    this.removeUserFromProject(projectName, userAdding, userToAdd);
                    users.remove(userToAdd);
                }
                
                try {
                    // Vamos verificar se o utilizador existe na lista de utilizadores do LDAP
                    System.out.println("A pedir a lista de utilizadores LDAP");
                    ArrayList<String> ldapUsers = Ldap.getUsers();
                    System.out.println(ldapUsers.size());
                    if (ldapUsers.contains(userToAdd)) {
                        File usersFile = new File(this.ssvnDir + projectName + "/users.txt");
                        ArrayList<User> allUsers = (ArrayList<User>) this.readFile(usersFile);

                        usersFile.delete();
                        //String newUser = new String(userToAdd + " " + permissions + " " + Boolean.toString(false));
                        User newUser = new User(userToAdd, permissions, false);
                        allUsers.add(newUser);
                        System.out.println("A escrever o novo utilizador: " + newUser.name() + ", " + newUser.permissions());

                        users.add(userToAdd);
                        this.projectsAndUsers.put(projectName, users);
                        this.writeDataToFileAndCreateMac(Utils.serialize(allUsers), usersFile);
                        ret = true;
                    } else {
                        System.err.println("Houve uma tentativa de adicionar um utilizador nao existente!");
                    }
                } catch (NamingException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            } else {
                System.err.println("Houve uma tentativa de mudanca de permissoes por alguem que nao as tinha,");
                System.err.println("Entao eu resolvi nem ouvir para nao ficarem chateados comigo.");
            }
        } else {
            System.err.println("Projecto nao existente ou permissoes invalidas!");
        }
        
        return ret;
    }
    
    private boolean removeUserFromProject(String projectName, String userRemoving, String userToRemove) {
        boolean ret = false;
        
        if(this.projectsAndOwners.get(projectName).equals(userRemoving) &&
                this.projectsAndUsers.get(projectName).contains(userToRemove) &&
                !userToRemove.equals(userRemoving)) {
            File users = new File(new String(this.ssvnDir + projectName + "/users.txt"));
            try {
                ArrayList<User> usersList = (ArrayList<User>)this.readFile(users);
                ArrayList<User> arrayToWrite = new ArrayList<User>();
                User[] allUsers = (User[]) usersList.toArray(new User[usersList.size()]);
                System.out.println("A iterar " + allUsers.length);
                for (int i = 0; i < allUsers.length; i++) {
                    if (!allUsers[i].name().equals(userToRemove)) {
                        System.out.println("A adicionar " + allUsers[i].name());
                        arrayToWrite.add(allUsers[i]);
                    }
                }
                this.writeDataToFileAndCreateMac(Utils.serialize(arrayToWrite), users);
                this.projectsAndUsers.get(projectName).remove(userToRemove);
                ret = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Opcoes invalidas na remoção do utilizador!");
        }
        
        return ret;
    }
    
    private String getPermissions(String projectName, String userName) {
        String permissions = null;
        boolean found = false;
        try {
            File usersFile = new File(this.ssvnDir + projectName + "/users.txt");

            ArrayList<User> usersList = (ArrayList<User>) this.readFile(usersFile);
            //System.out.println(usersList);
            if(usersList != null) {
                User[] usersArray = (User[]) usersList.toArray(new User[usersList.size()]);
                for (int i = 0; i < usersArray.length && !found; i++) {
                    if (usersArray[i].name().equals(userName)) {
                        permissions = usersArray[i].permissions();
                        found = true;
                    }
                }
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
        
        return permissions;
    }
}
