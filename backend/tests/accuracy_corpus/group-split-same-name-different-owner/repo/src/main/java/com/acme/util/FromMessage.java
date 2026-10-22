package com.acme.util;

public class FromMessage {
    private XmlPortMsg xmlPortMsg;

    public String lookup() {
        return xmlPortMsg.getPortID();
    }
}
