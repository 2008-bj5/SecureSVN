package seg004.ssvnserver;


import java.util.Hashtable;
import javax.naming.*;
import javax.naming.directory.*;
import java.util.ArrayList;

/**
Classe que recebe como parametros
um nome de utilizador e password
e tenta verificar se as credenciais
sao autenticas num servidor LDAP

-Djavax.net.ssl.trustStore=truststore.ks -Djava.naming.provider.url=ldaps://127.0.0.1:60000
 **/
public final class Ldap {

    private static DirContext ctx;
    
    public static boolean autentica(String user, String pass) throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, System.getProperty("java.naming.provider.url"));
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        env.put(Context.SECURITY_PRINCIPAL, user);
        env.put(Context.SECURITY_CREDENTIALS, pass);

        ctx = new InitialDirContext(env);
        ctx.close();
        return true;
    }

    public static ArrayList<String> getUsers() throws NamingException {

        ArrayList<String> users = new ArrayList<String>();
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        // Autenticacao como admin
        env.put(Context.PROVIDER_URL, System.getProperty("java.naming.provider.url"));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");
        
        // Criar o contexto de directorio inicial
        // Se as credenciais forem invalidas throws NamingException
        ctx = new InitialDirContext(env);
        Attributes matchAttributes = new BasicAttributes(true);
        matchAttributes.put(new BasicAttribute("cn"));
        NamingEnumeration ne = ctx.search("o=seg", matchAttributes);
        ne = ctx.list("o=seg");
        while (ne.hasMore()) {
            // Mostrar cn dos utilizadores existentes
            NameClassPair nc = (NameClassPair) ne.next();
            users.add(nc.getName().split("cn=")[1]);
        }
        //System.out.println(users);
        return users;
    }
}