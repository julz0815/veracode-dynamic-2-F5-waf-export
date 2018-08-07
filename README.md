# veracode-2-F5

The F5 Big-IP WAF is able to import XML files with flaws from dynamic scans of different vendors like Qualys, Rapid 7, White Hat or Trustwave. The solution I build is making use of their generic scanner import plugin. It's a fairly simple process, download the Veracode Dynamic scan detailed XML report and transform it using a XSLT transformation template. Please refer to the generic_scanner.xsd

The F5 possible values to identify flaws are named as following and I mapped to the Veracode CWE's accordingly.

F5 Flaw Category			CWE ID	Veracode CWE Name
 	 	 
* Other Application Attacks		296	Improper Following of Chain of Trust for Certificate Validation
* Other Application Attacks		297	Improper Validation of Host-specific Certificate Data
* Other Application Attacks		298	Improper Validation of Certificate Expiration
* Other Application Attacks		321	Use of Hard-coded Cryptographic Key
* Other Application Attacks		326	Inadequate Encryption Strength
* Other Application Attacks		327	Use of a Broken or Risky Cryptographic Algorithm
* Other Application Attacks		530	Exposure of Backup File to an Unauthorized Control Sphere
* Other Application Attacks		16	Configuration
* Other Application Attacks		642	External Control of Critical State Data
* Other Application Attacks		757	Selection of Less-Secure Algorithm During Negotiation (Algorithm Downgrade)
Authentication/Authorization Attacks	287	Improper Authentication
Authentication/Authorization Attacks	285	Improper Authorization
Authentication/Authorization Attacks	259	Use of Hard-coded Password
Authentication/Authorization Attacks	522	Insufficiently Protected Credentials
Clickjacking				693	Clickjacking/Content Security Policy insecure unsafe-inline directive used/Content Security Policy insecure unsafe-eval directive used
Command Execution			78	Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
Command Execution			78	Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
Cross Site Scripting (XSS)		79	Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
Cross Site Scripting (XSS)		80	Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
Cross Site Scripting (XSS)		83	Improper Neutralization of Script in Attributes in a Web Page
Cross-site Request Forgery		352	Cross-Site Request Forgery (CSRF)
Directory Indexing			548	Information Exposure Through Directory Listing
Forceful Browsing			538	File and Directory Information Exposure
HTTP Response Splitting			113	Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)
Information Leakage			200	Information Exposure
Information Leakage			209	Information Exposure Through an Error Message
Information Leakage			215	Information Exposure Through Debug Information
Information Leakage			526	Information Exposure Through Environmental Variables
Malicious File Upload			434	Unrestricted Upload of File with Dangerous Type
Mixed content found			830	Inclusion of Web Functionality from an Untrusted Source
Open redirect				601	URL Redirection to Untrusted Site (Open Redirect)
Path Traversal				22	Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
Remote File Include			98	Improper Control of Filename for Include/Require Statement in PHP Program (PHP File Inclusion)
Session Hijacking			384	Session Fixation
Set-Cookie doesn't use HTTPOnly keyword	402	Transmission of Private Resources into a New Sphere (Resource Leak)
Set-Cookie doesn't use Secure keyword	614	Sensitive Cookie in HTTPS Session Without Secure Attribute
SQL-Injection				89	Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
Unsafe CORS configuration		668	Exposure of Resource to Wrong Sphere
 

The XSLT template will transform the Veracode Dynamic scan results detailed xml report to F5's generic scanner format. The template is transform2F5.xslt.

The command to run the transformation is (on a mac) 

xsltproc  -o output.xml transform2F5.xslt detailedreport-xml-report.xml
and will produce a file that can easily be uploaded to the F5 Big-IP user interface and virtually patch the dynamic findings.


