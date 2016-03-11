%.html: %.yang docbook-xhtml-single.xsl
	# Validate first
	pyang --plugindir $(CURDIR)/../pyang --path $(CURDIR)/../modules $<
	pyang --plugindir $(CURDIR)/../pyang --path $(CURDIR)/../modules \
	-f docbook-reference $< | \
	xsltproc docbook-xhtml-single.xsl - >$@ || rm $@

all: example-adm.html

clean:
	rm example-adm.html