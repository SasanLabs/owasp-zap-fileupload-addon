package org.sasanlabs.fileupload.attacks.impl;

/** @author KSASAN preetkaran20@gmail.com */
public class ExtensionContentType {
    private String extension;
    private String contentType;

    public ExtensionContentType(String extension, String contentType) {
        super();
        this.extension = extension;
        this.contentType = contentType;
    }

    public String getExtension() {
        return extension;
    }

    public String getContentType() {
        return contentType;
    }
}
