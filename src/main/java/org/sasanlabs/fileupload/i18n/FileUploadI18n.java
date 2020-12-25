package org.sasanlabs.fileupload.i18n;

import java.util.ResourceBundle;
import org.parosproxy.paros.Constant;

/**
 * Message Bundle
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class FileUploadI18n {
    private static ResourceBundle message;

    public static void init() {
        message =
                ResourceBundle.getBundle(
                        FileUploadI18n.class.getPackage().getName() + ".Messages",
                        Constant.getLocale());
    }

    public static String getMessage(String key) {
        if (key != null && message != null && message.containsKey(key)) {
            return message.getString(key);
        }
        return "";
    }

    public static ResourceBundle getResourceBundle() {
        return message;
    }
}
