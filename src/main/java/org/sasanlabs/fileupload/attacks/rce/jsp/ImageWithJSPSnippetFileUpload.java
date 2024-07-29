/**
 * Copyright 2024 SasanLabs
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
package org.sasanlabs.fileupload.attacks.rce.jsp;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.impl.ContainsExpectedValueMatcher;

/**
 * @author preetkaran20@gmail.com KSASAN
 */
public class ImageWithJSPSnippetFileUpload extends AttackVector {

    private static final String GIF_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED =
            "R0lGODlhAQABAIAAAP///wAAACH5BAAAAAAAIf5JPCU9ICJJbWFnZVdpdGhKU1BTbmlwcGV0RmlsZVVwbG9hZF8iICsgIlNhc2FuTGFic18iICsgIlpBUF9JZGVudGlmaWVyIiAlPgAsAAAAAAEAAQAAAgJEAQA7";
    private static final String GIF_IMAGE_APPENDED_WITH_JSP_SNIPPET_BASE64_ENCODED =
            "R0lGODlhAQABAIAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOzwlPSAiSW1hZ2VXaXRoSlNQU25pcHBldEZpbGVVcGxvYWRfIiArICJTYXNhbkxhYnNfIiArICJaQVBfSWRlbnRpZmllciIgJT4K";

    // As JPEG is most widely used format for images hence in case application is
    // specifically
    // looking for JPEG magic numbers then this below configuration can help
    private static final String JPEG_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED =
            "/9j/4AAQSkZJRgABAQEAYABgAAD//gBLPCU9ICJJbWFnZVdpdGhKU1BTbmlwcGV0RmlsZVVwbG9hZF8iICsgIlNhc2FuTGFic18iICsgIlpBUF9JZGVudGlmaWVyIiAlPv/bAEMACAYGBwYFCAcHBwkJCAoMFA0MCwsMGRITDxQdGh8eHRocHCAkLicgIiwjHBwoNyksMDE0NDQfJzk9ODI8LjM0Mv/bAEMBCQkJDAsMGA0NGDIhHCEyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMv/AABEIAAEAAQMBIgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APf6KKKAP//Z";
    private static final String JPEG_IMAGE_APPENDED_WITH_JSP_SNIPPET_BASE64_ENCODED =
            "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2TwlPSAiSW1hZ2VXaXRoSlNQU25pcHBldEZpbGVVcGxvYWRfIiArICJTYXNhbkxhYnNfIiArICJaQVBfSWRlbnRpZmllciIgJT4K";

    private static final String FILE_EXPECTED_VALUE =
            "ImageWithJSPSnippetFileUpload_SasanLabs_ZAP_Identifier";

    private static final String BASE_FILE_NAME = "ImageWithJSPSnippetFileUpload_";

    private static final Map<VulnerabilityType, List<String>> PAYLOADS = getPayloads();

    private static Map<VulnerabilityType, List<String>> getPayloads() {
        Map<VulnerabilityType, List<String>> payloads = new HashMap<>();
        payloads.put(
                VulnerabilityType.RCE_GIF_JSP_FILE,
                Arrays.asList(
                        GIF_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED,
                        GIF_IMAGE_APPENDED_WITH_JSP_SNIPPET_BASE64_ENCODED));
        payloads.put(
                VulnerabilityType.RCE_JPEG_JSP_FILE,
                Arrays.asList(
                        JPEG_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED,
                        JPEG_IMAGE_APPENDED_WITH_JSP_SNIPPET_BASE64_ENCODED));
        return payloads;
    }

    private static final List<FileInformationProvider> FILE_PARAMETERS_EXTENDED =
            FileUploadUtils.getFileInformationProvidersExtendedJsp(BASE_FILE_NAME);
    private static final List<FileInformationProvider> FILE_PARAMETERS_DEFAULT =
            FileUploadUtils.getFileInformationProvidersDefaultJsp(
                    BASE_FILE_NAME, FileUploadUtils.JSP_FILE_EXTENSION);

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result = false;
        for (VulnerabilityType vulnerabilityType : PAYLOADS.keySet()) {
            for (String payloads : PAYLOADS.get(vulnerabilityType)) {
                byte[] imagePayload = Base64.getDecoder().decode(payloads);
                HttpMessage originalMessage = fileUploadAttackExecutor.getOriginalHttpMessage();
                String charSet = originalMessage.getRequestHeader().getCharset();
                Charset requestCharSet =
                        charSet != null ? Charset.forName(charSet) : StandardCharsets.ISO_8859_1;
                String requestPayload = new String(imagePayload, requestCharSet);
                result =
                        this.genericAttackExecutor(
                                fileUploadAttackExecutor,
                                requestPayload,
                                FILE_PARAMETERS_DEFAULT,
                                new ContainsExpectedValueMatcher(FILE_EXPECTED_VALUE),
                                vulnerabilityType);

                if (!result
                        && fileUploadAttackExecutor
                                .getFileUploadScanRule()
                                .getAttackStrength()
                                .equals(AttackStrength.INSANE)) {
                    result =
                            this.genericAttackExecutor(
                                    fileUploadAttackExecutor,
                                    requestPayload,
                                    FILE_PARAMETERS_EXTENDED,
                                    new ContainsExpectedValueMatcher(FILE_EXPECTED_VALUE),
                                    vulnerabilityType);
                }
                if (result) {
                    return result;
                }
            }
        }
        return result;
    }
}
