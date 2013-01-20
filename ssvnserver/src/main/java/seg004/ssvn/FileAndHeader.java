/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package seg004.ssvn;

import seg004.ssvn.Header;

/**
 *
 * @author vasco
 */
public class FileAndHeader implements java.io.Serializable {
    private Header header;
    private byte[] contents;
    
    public FileAndHeader(Header header, byte[] contents) {
        this.header = header;
        this.contents = contents;
    }
    
    public byte[] getContents() {
        return this.contents;
    }
    
    public Header getHeader() {
        return this.header;
    }
}
