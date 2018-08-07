<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:vc="https://www.veracode.com/schema/reports/export/1.0">
<xsl:output encoding="UTF-8" indent="yes" method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/" >
<scanner_vulnerabilities>
<xsl:attribute name="version"><xsl:value-of select="vc:detailedreport/@report_format_version"/></xsl:attribute>
<xsl:for-each select="vc:detailedreport/vc:severity/vc:category/vc:cwe/vc:dynamicflaws/vc:flaw">
<vulnerability>

<!-- MAP CWE's to F5 naming convention -->
<xsl:choose>
	<xsl:when test="((@cweid='200') or (@cweid='209') or (@cweid='215') or  (@cweid='526'))">
		<attack_type>Information Leakage</attack_type>
	</xsl:when>
	<xsl:when test="((@cweid='287') or (@cweid='285') or (@cweid='259') or  (@cweid='522'))">
                <attack_type>Authentication/Authorization Attacks</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='693'">
                <attack_type>Clickjacking</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='78'">
                <attack_type>Command Execution</attack_type>
        </xsl:when>
	<xsl:when test="((@cweid='79') or (@cweid='80') or (@cweid='83'))">
                <attack_type>Cross Site Scripting (XSS)</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='352'">
                <attack_type>Cross-site Request Forgery</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='548'">
                <attack_type>Directory Indexing</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='538'">
                <attack_type>Forceful Browsing</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='113'">
                <attack_type>HTTP Response Splitting</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='434'">
                <attack_type>Malicious File Upload</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='830'">
                <attack_type>Mixed content found</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='601'">
                <attack_type>Open redirect</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='22'">
                <attack_type>Path Traversal</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='98'">
                <attack_type>Remote File Include</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='384'">
                <attack_type>Session Hijacking</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='402'">
                <attack_type>Set-Cookie does not use HTTPOnly keyword</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='614'">
                <attack_type>Set-Cookie does not use Secure keyword</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='89'">
                <attack_type>SQL-Injection</attack_type>
        </xsl:when>
	<xsl:when test="@cweid='668'">
                <attack_type>Unsafe CORS configuration</attack_type>
        </xsl:when>
	<xsl:otherwise>
	        <attack_type>Other Application Attacks</attack_type>
        </xsl:otherwise>
</xsl:choose>
<!-- MAP CWE's to F5 naming convention -->

<name><xsl:value-of select="@categoryname"/></name>
<url><xsl:value-of select="@url"/></url>

<!-- If cookie vuln print cookie tag otherwiese if parameter exists print parameter tag, otherwiese blank -->
<xsl:choose>
	<xsl:when test="((@cweid='402') or (@cweid='614'))">
		<cookie><xsl:value-of select="@vuln_parameter"/></cookie>
	</xsl:when>
        <xsl:otherwise test="@vuln_parameter!=''">
		<parameter><xsl:value-of select="@vuln_parameter"/></parameter>
        </xsl:otherwise>
</xsl:choose>
<!-- If parameter exists, otherwiese blank -->
<xsl:choose>
        <xsl:when test="@severity='1'">
                <threat>info</threat>
        </xsl:when>
	<xsl:when test="@severity='2'">
                <threat>low</threat>
        </xsl:when>
	<xsl:when test="@severity='3'">
                <threat>medium</threat>
        </xsl:when>
	<xsl:when test="@severity='4'">
                <threat>high</threat>
        </xsl:when>
	<xsl:when test="@severity='5'">
                <threat>critical</threat>
        </xsl:when>
	<xsl:when test="@severity='6'">
                <threat>urgent</threat>
        </xsl:when>
</xsl:choose>
<!-- Map Veracode Severity to F5 threat level -->

<!-- Leave score blank or jsut set to 0, this is about traffic learning -->
<score>0</score>
<!-- Leave score blank or jsut set to 0, this is about traffic learning -->

<!-- Map Veracode Severity to F5 severity level -->
<xsl:choose>
        <xsl:when test="@severity='1'">
                <severity>info</severity>
        </xsl:when>
        <xsl:when test="@severity='2'">
                <severity>low</severity>
        </xsl:when>
        <xsl:when test="@severity='3'">
                <severity>medium</severity>
        </xsl:when>
        <xsl:when test="@severity='4'">
                <severity>high</severity>
        </xsl:when>
        <xsl:when test="@severity='5'">
                <severity>critical</severity>
        </xsl:when>
        <xsl:when test="@severity='6'">
                <severity>urgent</severity>
        </xsl:when>
</xsl:choose>
<!-- Map Veracode Severity to F5 severity level -->

<!-- Map Veracode remediation status to F5 status -->
<xsl:choose>
	<xsl:when test="@mitigation_status='accepted'">
                <status>mitigated</status>
        </xsl:when>
	<xsl:otherwise>
		<status>open</status>
        </xsl:otherwise>
</xsl:choose>
<!-- Map Veracode remediation status to F5 status -->

<opened>1</opened>

</vulnerability>
</xsl:for-each>
</scanner_vulnerabilities>
</xsl:template>
</xsl:stylesheet>

