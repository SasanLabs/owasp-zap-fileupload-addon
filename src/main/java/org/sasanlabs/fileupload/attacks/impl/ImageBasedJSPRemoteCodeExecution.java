package org.sasanlabs.fileupload.attacks.impl;

import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.FileUploadException;

public class ImageBasedJSPRemoteCodeExecution implements AttackVector {

    private static final String GIF_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED =
            "R0lGODlhAQABAHAAACH5BAUAAAAAIf4nPCVAIHBhZ2UgaW1wb3J0PWphdmEudXRpbC4qLGphdmEuaW8uKiU+ACwAAAAAAQABAAACAkQBADs=";

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        // TODO Auto-generated method stub
        return false;
    }
}
