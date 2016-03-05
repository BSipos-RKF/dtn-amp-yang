draft-bsipos-dtn-amp-yang-mod.xml: include-and-strip.xsl draft-bsipos-dtn-amp-yang.xml *.yang
	xsltproc --output draft-bsipos-dtn-amp-yang-mod.xml --xinclude include-and-strip.xsl draft-bsipos-dtn-amp-yang.xml

draft-bsipos-dtn-amp-yang.txt: draft-bsipos-dtn-amp-yang-mod.xml
	xml2rfc -o draft-bsipos-dtn-amp-yang.txt draft-bsipos-dtn-amp-yang-mod.xml

draft-bsipos-dtn-amp-yang.html: draft-bsipos-dtn-amp-yang-mod.xml
	xml2rfc --html -o draft-bsipos-dtn-amp-yang.html draft-bsipos-dtn-amp-yang-mod.xml

all: draft-bsipos-dtn-amp-yang.html draft-bsipos-dtn-amp-yang.txt
