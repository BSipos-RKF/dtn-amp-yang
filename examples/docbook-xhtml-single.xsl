<?xml version="1.0" ?>
<!-- This stylesheet takes a DocBook v5.0 reference set and outputs
directly to stdout.

It can be invoked using the command:
xsltproc -\-nonet -\-xinclude <this filename> <refentry filename>
  -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl"/>
  <!-- output options -->
  <xsl:param name="base.dir">html/</xsl:param>
  <xsl:param name="html.stylesheet">reference.css</xsl:param>

  <xsl:param name="toc.max.depth" select="2"/>
  <xsl:param name="generate.section.toc.level" select="0"/>

  <xsl:param name="refentry.generate.title" select="1"/>
  <xsl:param name="refentry.generate.name" select="0"/>
</xsl:stylesheet>
