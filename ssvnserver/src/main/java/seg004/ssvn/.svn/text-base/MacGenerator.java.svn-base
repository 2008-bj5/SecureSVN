package seg004.ssvn;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Silvana
 */
public class MacGenerator {
    private Mac mac = null;
    
    public MacGenerator(byte[] key) {
        try {
            SecretKey macKey = new SecretKeySpec(key, "HmacSHA1");
            mac = Mac.getInstance("HmacSHA1");
            mac.init(macKey);
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(MacGenerator.class.getName()).log(Level.SEVERE, null, e);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MacGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    // TODO: Partir o file em varios bytes
    public byte[] geraMac(byte[] file){
        return mac.doFinal(file);
    }
    
    public boolean comparaMac(byte[] fileMac, byte[] file){
        if(!Arrays.equals(fileMac, geraMac(file))){
            System.out.println("Ficheiro pode estar corrompido");
            return false;
        } else {
            return true;
        }
    }
    
    private byte[] leBytes(File file){
        FileInputStream in = null;
        byte[] bytes = null;
        try {
            in = new FileInputStream(file);
            bytes = new byte[(int)file.length()];
            in.read(bytes);
            in.close();
            
        } catch (IOException ex) {
            Logger.getLogger(MacGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
                Logger.getLogger(MacGenerator.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return bytes;
    }
}
