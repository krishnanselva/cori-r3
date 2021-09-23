package com.corizance.enclave;

import com.r3.conclave.enclave.Enclave;
import com.r3.conclave.mail.EnclaveMail;

public class ReverseEnclave extends Enclave {
    @Override
    public byte[] receiveFromUntrustedHost(byte[] bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            result[i] = bytes[bytes.length - 1 - i];
        return result;
    }
    @Override
    protected void receiveMail(long id, EnclaveMail mail, String routingHint) {
        byte[] reversed = receiveFromUntrustedHost(mail.getBodyAsBytes());
        byte[] responseBytes = postOffice(mail).encryptMail(reversed);
        postMail(responseBytes, routingHint);
    }


}
