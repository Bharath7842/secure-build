package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XmlReader {
    private static final Logger log = LoggerFactory.getLogger(XmlReader.class);

    public void read(java.io.InputStream in) throws Exception {
        try {
            javax.xml.parsers.SAXParserFactory.newInstance().newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
        } catch (org.xml.sax.SAXException e) {
            log.warn("failed {}", e.getMessage());
        }
    }
}
