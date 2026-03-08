package com.veryrandomcreator;

import org.bouncycastle.asn1.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

// TODO:
//   - Modify for long-term support (for when the certificate expires)
//      - Handle certificate expiration
//      - Change google's hardcoded root certificate to one that handles rotating certificates
//      - https://developer.android.com/privacy-and-security/security-key-attestation
public class Main {
    public static final String GITHUB_BUILD_HASH = "3C:1C:DC:3B:CF:FA:5D:85:0B:4E:41:A6:A9:68:F7:09:39:FD:08:8B:1A:E1:A0:5D:FC:B3:48:CC:16:7F:04:3C"
            .replaceAll(":", "");

    // make it so you can just put the files in args. cli
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            CertificateException, IOException, InvalidAlgorithmParameterException {
        String pdfPath = null;
        String signaturePath = null;
        String pemPath = null;
        boolean showHash = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-pdf":
                    if (i + 1 < args.length)
                        pdfPath = args[++i];
                    break;
                case "-signature":
                    if (i + 1 < args.length)
                        signaturePath = args[++i];
                    break;
                case "-pem":
                    if (i + 1 < args.length)
                        pemPath = args[++i];
                    break;
                case "-showhash":
                    showHash = true;
                    break;
            }
        }

        if (pdfPath == null || signaturePath == null || pemPath == null) {
            System.out.println("Error: Missing required arguments.");
            System.out.println(
                    "Usage: java -jar RentHelpCLI.jar -pdf <.pdf file> -signature <.sig file> -pem <.pem.crt file> [-showhash]");
            return;
        }

        System.out.println("Starting Verification Process...\n");

        // 1: Loading the files
        System.out.println("1. Loading files into memory...");
        byte[] pdfBytes = Files.readAllBytes(Paths.get(pdfPath));
        byte[] signatureBytes = Files.readAllBytes(Paths.get(signaturePath));
        byte[] pemBytes = Files.readAllBytes(Paths.get(pemPath));

        // 2: Parse the Certificate Chain
        System.out.println("2. Parsing the X.509 PEM Certificate Chain...");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = certFactory.generateCertificates(new ByteArrayInputStream(pemBytes));

        Iterator<? extends Certificate> iterator = certs.iterator();

        X509Certificate leafCert = (X509Certificate) iterator.next();

        // 3: Verifying certificate signature
        System.out.println("3. Verifying the cryptographic signature...");
        PublicKey hardwarePublicKey = leafCert.getPublicKey();

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(hardwarePublicKey);

        ecdsaVerify.update(pdfBytes);

        boolean isSignatureValid = ecdsaVerify.verify(signatureBytes);

        if (isSignatureValid) {
            System.out.println("Verification SUCCESS: The PDF signature is valid. PDF was unaltered");
        } else {
            System.out.println("Verification FAILED: The PDF was altered or the signature is counterfeit.");
            return;
        }

        // 4: Parse Attestation Extension

        System.out.println("4. Analyzing Device and App Integrity...");

        // Google's official Object Identifier (OID) for Android Key Attestation
        String attestationOID = "1.3.6.1.4.1.11129.2.1.17";
        byte[] extensionValue = leafCert.getExtensionValue(attestationOID);

        if (extensionValue == null) {
            System.out.println("Attestation FAILED: Attestation Extension missing!");
            return;
        }

        ASN1OctetString extOctet = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
        ASN1Sequence keyDescription = (ASN1Sequence) ASN1Primitive.fromByteArray(extOctet.getOctets());

        // 2. Catch the Rooted Phone (Hardware Level)

        ASN1Sequence teeEnforced = (ASN1Sequence) keyDescription.getObjectAt(7);
        boolean foundRot = false;

        for (int i = 0; i < teeEnforced.size(); i++) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) teeEnforced.getObjectAt(i);

            if (taggedObject.getTagNo() == 704) { // 704 is the official tag for RootOfTrust
                foundRot = true;
                ASN1Sequence rotSequence = ASN1Sequence.getInstance(taggedObject, true);

                boolean isLocked = ((ASN1Boolean) rotSequence.getObjectAt(1)).isTrue();
                int bootState = ((ASN1Enumerated) rotSequence.getObjectAt(2)).getValue().intValue();

                String stateStr = (bootState == 0) ? "VERIFIED"
                        : (bootState == 1) ? "SELF_SIGNED"
                                : (bootState == 2) ? "UNVERIFIED (Rooted/Unlocked)" : "FAILED";

                System.out.println("Bootloader Locked: " + isLocked);
                System.out.println("Verified Boot State: " + stateStr);

                if (!isLocked || bootState != 0) {
                    System.out.println("Device Integrity FAILED: DEVICE IS ROOTED OR COMPROMISED!");
                } else {
                    System.out.println("Device Integrity SUCCESS: Device is physically secure.");
                }
                break;
            }
        }
        if (!foundRot)
            System.out.println("Device Integrity FAILED: No Root of Trust found.");

        // 3. Extract the App's GitHub Signature (Software Level)
        // Application ID is located inside softwareEnforced (Index 6 of KeyDescription)
        ASN1Sequence softwareEnforced = (ASN1Sequence) keyDescription.getObjectAt(6);
        boolean foundAppId = false;

        for (int i = 0; i < softwareEnforced.size(); i++) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) softwareEnforced.getObjectAt(i);

            if (taggedObject.getTagNo() == 709) { // 709 is the official tag for AttestationApplicationId
                foundAppId = true;
                ASN1OctetString appIdOctet = ASN1OctetString.getInstance(taggedObject, true);
                ASN1Sequence appIdSequence = (ASN1Sequence) ASN1Primitive.fromByteArray(appIdOctet.getOctets());

                // Index 1 is the signatureDigests SET
                ASN1Set signatureDigests = (ASN1Set) appIdSequence.getObjectAt(1);
                ASN1OctetString signatureDigest = (ASN1OctetString) signatureDigests.getObjectAt(0);

                byte[] apkHash = signatureDigest.getOctets();
                StringBuilder hexString = new StringBuilder();
                for (byte b : apkHash) {
                    hexString.append(String.format("%02X", b));
                }

                System.out.println("Extracted App Signature (SHA-256): " + hexString.toString());
                if (hexString.toString().equals(GITHUB_BUILD_HASH)) {
                    System.out.println("App Integrity SUCCESS: App hash matches github apk hash!");
                }
                break;
            }
        }
        if (!foundAppId)
            System.out.println("App Integrity Failed: Could not find App ID.");

        if (showHash) {
            // 4. Extract the Challenge (The Block Hash)
            ASN1OctetString challengeOctet = (ASN1OctetString) keyDescription
                    .getObjectAt(4);

            byte[] challengeBytes = challengeOctet.getOctets();

            String extractedBlockHash = new String(challengeBytes);

            System.out.println("Extracted Challenge (Block Hash): " + extractedBlockHash);

            // 5. Fetch timestamp of hash

            URL url = new URL("https://mempool.space/api/block/" + extractedBlockHash);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String data = in.readLine();
            in.close();

            long timestamp = 0;
            for (String item : data.split(",")) {
                if (item.contains("timestamp")) {
                    timestamp = Long.parseLong(item.split(":")[1]);

                    ZonedDateTime blockTime = Instant.ofEpochSecond(timestamp).atZone(ZoneId.systemDefault());
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss z");

                    System.out.println("Hash Timestamp: " + blockTime.format(formatter));
                }
            }
            if (timestamp == 0) {
                System.out.println("HASH TIMESTAMP FAILED!");
            }
        }

        // Todo: Running out of time to implement, but the certificate still needs to be verified to have full coverage.
    }
}