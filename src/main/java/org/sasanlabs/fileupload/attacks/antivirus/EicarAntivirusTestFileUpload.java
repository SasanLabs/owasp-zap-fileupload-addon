/**
 * Copyright 2020 SasanLabs
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sasanlabs.fileupload.attacks.antivirus;

import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.exception.FileUploadException;

/**
 * {@code EicarAntivirusTestFileUpload} attack vector is used to check the if antivirus is present
 * and working properly by upload the Eicar file. General idea is to upload the Eicar Test file and
 * if we are able to download it again then that means there are chances that Antivirus is either
 * not present or not working properly.
 *
 * <p>For more information about Eicar file please visit <a
 * href="https://en.wikipedia.org/wiki/EICAR_test_file">Eicar File Wiki link</a>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class EicarAntivirusTestFileUpload implements AttackVector {

    private static final String EICAR_FILE_CONTENT =
            "WDVPIVAlQEFQWzRcUFpYNTQ"
                    + "oUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVEl"
                    + "WSVJVUy1URVNULUZJTEUhJEgrSCo=";

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        // TODO Auto-generated method stub
        return false;
    }
}
