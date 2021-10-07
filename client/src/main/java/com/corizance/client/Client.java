package com.corizance.client;

import com.r3.conclave.client.EnclaveConstraint;
import com.r3.conclave.client.InvalidEnclaveException;
import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.mail.Curve25519PrivateKey;
import com.r3.conclave.mail.EnclaveMail;
import com.r3.conclave.mail.PostOffice;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

public class Client {
    public static void main(String[] args) throws IOException, InvalidEnclaveException {
        if (args.length == 0) {
            System.err.println("Please pass the string to reverse on the command line");
            return;
        }
        String toReverse = String.join(" ", args);

        // Connect to the host, it will send us a remote attestation (EnclaveInstanceInfo).
        Socket socket = new Socket("localhost", 9999);
        DataInputStream fromHost = new DataInputStream(socket.getInputStream());
        byte[] attestationBytes = new byte[fromHost.readInt()];
        fromHost.readFully(attestationBytes);
        EnclaveInstanceInfo attestation = EnclaveInstanceInfo.deserialize(attestationBytes);
        // Check it's the enclave we expect. This will throw InvalidEnclaveException if not valid.
        EnclaveConstraint.parse("S:0000000000000000000000000000000000000000000000000000000000000000 PROD:1 SEC:INSECURE").check(attestation);
        PrivateKey myKey = Curve25519PrivateKey.random();
        PostOffice postOffice = attestation.createPostOffice(myKey, "reverse");
        byte[] encryptedMail = postOffice.encryptMail(toReverse.getBytes(StandardCharsets.UTF_8));
        System.out.println("Sending the encrypted mail to the host.");
        DataOutputStream toHost = new DataOutputStream(socket.getOutputStream());
        toHost.writeInt(encryptedMail.length);
        toHost.write(encryptedMail);

// Enclave will mail us back.
        byte[] encryptedReply = new byte[fromHost.readInt()];
        System.out.println("Reading reply mail of length " + encryptedReply.length + " bytes.");
        fromHost.readFully(encryptedReply);

// The same post office will decrypt the response.
        EnclaveMail reply = postOffice.decryptMail(encryptedReply);
        System.out.println("Enclave reversed '" + toReverse + "' and gave us the answer '" + new String(reply.getBodyAsBytes()) + "'");

        socket.close();
    }
}