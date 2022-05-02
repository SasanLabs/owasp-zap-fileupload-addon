# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
 - Ensure i18n resources are always initialized.

## [1.1.0] - 2021-09-16
 - Scan rule for uploading:
 	- HTACCESS file
 	- PHP and its variants
 	- JPEG AND GIF images with PHP code snippet
 - Skipping the scan rule initialization if add-on configuration is not present.

## [1.0.1] - 2021-08-19
 - Minor change
   - Scan rule will only execute if add-on configuration is specified.

## [1.0.0] - 2021-08-05
 - First version of FileUpload Addon.
   - Contains scan rule for finding vulnerabilities related to File Upload.
   - Types of uploaded files include:
   	 - HTML and its variants 
   	 - JSP and its variants
   	 - JPEG and GIF images
   	 - EICAR file
   	 - SVG images