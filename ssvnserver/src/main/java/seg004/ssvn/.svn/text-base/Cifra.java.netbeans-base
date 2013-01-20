package seg004.ssvn;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/*
 * To change this template, choose Tools | Templates and open the template in
 * the editor.
 */
/**
 *
 * @author Silvana
 */
public class Cifra {
    private Cipher encrypt = null;
    private Cipher decrypt = null;

    public Cifra(byte[] chave) {
        try {
            SecretKey key = new SecretKeySpec(chave, "AES");
            // Initialization Vector para CBC
            byte[] iv ={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public byte[] cifra(byte[] fic) {
        if(encrypt == null) {
            System.err.println("Objectos de cifra/decifra nao inicializados!");
            return null;
        }
        byte[] encrypted = null;
        try {
            encrypted = encrypt.doFinal(fic);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            return encrypted;
        }

    }

    public byte[] decifra(byte[] input) {
        if(decrypt == null) {
            System.err.println("Objectos de cifra/decifra nao inicializados!");
            return null;
        }
        byte[] decrypted = null;
        try {
            decrypted = decrypt.doFinal(input);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Cifra.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            return decrypted;
        }
    }
}
