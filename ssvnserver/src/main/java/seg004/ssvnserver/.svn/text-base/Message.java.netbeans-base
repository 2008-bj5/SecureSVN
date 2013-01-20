/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package seg004.ssvnserver;

/**
 *
 * @author silvana
 */
public final class Message implements java.io.Serializable {
    public static final int LOGIN = 0;
    public static final int LOGOUT = 1;
    public static final int CREATE = 2;
    public static final int DESTROY = 3; 
    public static final int ADDUSER = 4;
    public static final int RMVUSER = 5;
    public static final int GET = 6;
    public static final int LIST = 7;
    public static final int PUT = 8;
    public static final int DEL = 9;
    
    private String user;
    private String userToAdd;
    private String pass;
    private int tipo;
    private String file;
    private String project;
    private String permission;
    private int version;
    private String comment;
    private Object data;
    private boolean all;
    
    public final void setAll(boolean all) {
        this.all = all;
    }
    
    public final boolean getAll() {
        return this.all;
    }
    
    public final void setPass(String pass){
       this.pass = pass;
    }
    
    public final void setUserToAdd(String user) {
        this.userToAdd = user;
    }
    
    public final String getUserToAdd() {
        return this.userToAdd;
    }
    
    public final String getUser(){
        return user;
    }
    
    public final String getPass(){
        return pass;
    }
    
    public final void setUser(String user){
        this.user = user;
    }
    
    
    public final void setType(int tipo){
        this.tipo = tipo;
    }
    
    public final int getType(){
        return tipo;
    }

    public final String getFile() {
        return file;
    }

    public final int getVersion(){
        return version;
    }
    
    public final void setVersion(int version){
        this.version = version;
    }
    
    public final String getPermission(){
        return permission;
    }
    
    public final void setPermission(String permission){
        this.permission = permission;
    }
    
    public final void setFile(String file) {
        this.file = file;
    }

    public final String getProject() {
        return project;
    }
    
    public final void setProject(String project){
        this.project = project;
    }

    public final void setComment(String comment) {
        this.comment = comment;
    }
    
    public final String getComment(){
        return comment;
    }
    
    public final void setData(Object o) {
        this.data = o;
    }
    
    public final Object getData() {
        return this.data;
    }
}
