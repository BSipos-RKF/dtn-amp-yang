%.html: %.yang docbook-xhtml-single.xsl
	pyang --plugindir $(CURDIR)/../pyang --path $(CURDIR)/../modules \
	-f docbook-reference $< | \
	xsltproc docbook-xhtml-single.xsl - >$@ || rm $@

all: example-adm.html
