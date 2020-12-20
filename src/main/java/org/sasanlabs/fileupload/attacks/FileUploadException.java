package org.sasanlabs.fileupload.attacks;

/**
 * {@code FileUploadException} is an exception class for FileUpload Scan Rule. It wraps around
 * multiple other types of exception and might be very useful in future.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class FileUploadException extends Exception {
    private static final long serialVersionUID = 372527297369183960L;

    public FileUploadException(Throwable th) {
        super(th);
    }

    public FileUploadException(String message, Throwable th) {
        super(message, th);
    }
}
