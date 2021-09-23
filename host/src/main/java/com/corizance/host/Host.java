package com.corizance.host;

import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.host.AttestationParameters;
import com.r3.conclave.host.EnclaveHost;
import com.r3.conclave.host.EnclaveLoadException;
import com.r3.conclave.host.MailCommand;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

public class Host {
    public static void main(String[] args) throws Exception {
//        EnclaveHost.getCapabilitiesDiagnostics();
        try {
            EnclaveHost.checkPlatformSupportsEnclaves(true);
            System.out.println("This platform supports enclaves in simulation, debug and release mode.");
        } catch (EnclaveLoadException e) {
            System.out.println("This platform does not support hardware enclaves: " + e.getMessage());
        }

        String className = "com.corizance.enclave.ReverseEnclave";
        try (EnclaveHost enclave = EnclaveHost.load(className)) {
            // Start it up.
            AtomicReference<byte[]> mailToSend = new AtomicReference<>();
            enclave.start(new AttestationParameters.DCAP(), (commands) -> {
                for (MailCommand command : commands) {
                    if (command instanceof MailCommand.PostMail) {
                        mailToSend.set(((MailCommand.PostMail) command).getEncryptedBytes());
                    }
                }
            });

            System.out.println(callEnclave(enclave, "Hello world!"));
            // !dlrow olleH      :-)

            final EnclaveInstanceInfo attestation = enclave.getEnclaveInstanceInfo();
            final byte[] attestationBytes = attestation.serialize();
            System.out.println(EnclaveInstanceInfo.deserialize(attestationBytes));


            int port = 9999;
            System.out.println("Listening on port " + port + ". Use the client app to send strings for reversal.");
            ServerSocket acceptor = new ServerSocket(port);
            Socket connection = acceptor.accept();

// Just send the attestation straight to whoever connects. It's signed so that's MITM-safe.
            DataOutputStream output = new DataOutputStream(connection.getOutputStream());
            output.writeInt(attestationBytes.length);
            output.write(attestationBytes);

// Now read some mail from the client.
            DataInputStream input = new DataInputStream(connection.getInputStream());
            byte[] mailBytes = new byte[input.readInt()];
            input.readFully(mailBytes);

// Deliver it. The enclave will give us some mail to reply with via the callback we passed in
// to the start() method.
            enclave.deliverMail(1, mailBytes, "routingHint");
            byte[] toSend = mailToSend.getAndSet(null);
            output.writeInt(toSend.length);
            output.write(toSend);

        }
    }

    public static String callEnclave(EnclaveHost enclave, String input) {
        // TODO: Fill this out.
        // We'll convert strings to bytes and back.
        return new String(enclave.callEnclave(input.getBytes()));
    }
}
