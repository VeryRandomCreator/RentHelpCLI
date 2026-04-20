package com.veryrandomcreator;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.bouncycastle.asn1.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

public class Main {
    public static final String[] ATTESTATION_SECURITY_LEVELS = {"SOFTWARE", "TEE", "STRONGBOX"};

    public static final String[] ROOT_FILES = {
            "/roots/google_root_1.pem",
            "/roots/google_root_2.pem",
            "/roots/google_root_legacy_1.pem",
            "/roots/google_root_legacy_2.pem",
            "/roots/google_root_legacy_3.pem"
    };

    public static final String GITHUB_BUILD_HASH = "05:92:64:62:B7:A5:70:48:63:01:77:54:96:F8:0D:D1:12:94:37:25:E5:11:7D:9C:66:26:22:75:F9:7D:05:3C"
            .replaceAll(":", "");

    // make it so you can just put the files in args. cli
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            CertificateException, IOException, InvalidAlgorithmParameterException {
        String pdfPath = null;
        String signaturePath = null;
        String pemPath = null;

        for (int i = 0; i < args.length; i++) { // TODO: HANDLE IF ANY OF THE FILE NAMES HAVE SPACES
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
            }
        }

        if (pdfPath == null || signaturePath == null || pemPath == null) {
            System.out.println("Error: Missing required arguments.");
            System.out.println("Usage: java -jar RentHelpCLI.jar -pdf <.pdf file> -signature <.sig file> -pem <.pem.crt file> [-showhash]");
            return;
        }

        System.out.println("Starting Verification Process...\n");

        // 1: Loading the files
        System.out.println("1. Loading files into memory...");
        byte[] pdfBytes = Files.readAllBytes(Paths.get(pdfPath));
        byte[] signatureBytes = Files.readAllBytes(Paths.get(signaturePath));
        byte[] pemBytes = Files.readAllBytes(Paths.get(pemPath));

        System.out.println("2. Parsing the X.509 PEM Certificate Chain...");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        Collection<? extends Certificate> certs = certFactory.generateCertificates(new ByteArrayInputStream(pemBytes));

        // fix numbers: Verify Certificate

        Set<TrustAnchor> trustAnchors = new HashSet<>();

        for (String root : ROOT_FILES) {
            try (InputStream is = Main.class.getResourceAsStream(root)) {
                if (is == null) {
                    throw new RuntimeException("Missing root certificate: " + root);
                }

                X509Certificate rootCert = (X509Certificate) certFactory.generateCertificate(is);
                trustAnchors.add(new TrustAnchor(rootCert, null));
            }
        }

        List<? extends Certificate> certList = new ArrayList<>(certs);
        CertPath certPath = certFactory.generateCertPath(certList);

        PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
        pkixParameters.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        try {
            validator.validate(certPath, pkixParameters);
            System.out.println("Chain of Trust SUCCESS: Chain anchors to Google Root CA");
        } catch (Exception e) {
            System.out.println("Chain of Trust FAILED: " + e.getMessage());
            return;
        }

        // 2: Parse the Certificate Chain

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

        System.out.println("4. Analyzing Device, App, and Key Integrity...");

        // Google's official Object Identifier (OID) for Android Key Attestation
        String attestationOID = "1.3.6.1.4.1.11129.2.1.17";
        byte[] extensionValue = leafCert.getExtensionValue(attestationOID);

        if (extensionValue == null) {
            System.out.println("Attestation FAILED: Attestation Extension missing!");
            return;
        }

        ASN1OctetString extOctet = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
        ASN1Sequence keyDescription = (ASN1Sequence) ASN1Primitive.fromByteArray(extOctet.getOctets());

        int attestationSecurityLevel = ((ASN1Enumerated) keyDescription.getObjectAt(1)).getValue().intValue();

        int keymasterSecurityLevel = ((ASN1Enumerated) keyDescription.getObjectAt(3)).getValue().intValue();

        String secLevel = attestationSecurityLevel >= 0 && attestationSecurityLevel <= 2 ?
                ATTESTATION_SECURITY_LEVELS[attestationSecurityLevel] : "UNKNOWN";

        System.out.println("Attestation Security Level: " + secLevel + " (" + attestationSecurityLevel + ")");

        if (attestationSecurityLevel == 0) {
            System.out.println("Security Level FAILED: Software generated key. Unsecure.");
            return;
        }

        if (keymasterSecurityLevel == 0) {
            System.out.println("Security Level FAILED: Attestation was performed in software. Untrustworthy.");
            return;
        }

        System.out.println("Security Level SUCCESS: Key is hardware-backed");

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
                    return;
                } else {
                    System.out.println("Device Integrity SUCCESS: Device is physically secure.");
                }
                break;
            }
        }
        if (!foundRot) {
            System.out.println("Device Integrity FAILED: No Root of Trust found.");
            return;
        }

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
                } else {
                    System.out.println("App Integrity FAILED: App hash does not match github apk hash!");
                    return;
                }
                break;
            }
        }
        if (!foundAppId) {
            System.out.println("App Integrity Failed: Could not find App ID.");
            return;
        }

        // 4. Extract the Challenge (The Block Hash)
        ASN1OctetString challengeOctet = (ASN1OctetString) keyDescription
                .getObjectAt(4);

        byte[] challengeBytes = challengeOctet.getOctets();

        String extractedBlockHash = new String(challengeBytes, StandardCharsets.UTF_8);

        System.out.println("Extracted Challenge (Block Hash): " + extractedBlockHash);

        if (!extractedBlockHash.matches("[0-9a-fA-F]{64}")) {
            System.out.println("Hash FAILED: Challenge is not a valid block hash format.");
            return;
        }

        // 5. Fetch timestamp of hash

        String data;
        try {
            URL url = new URL("https://mempool.space/api/block/" + extractedBlockHash);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int responseCode = conn.getResponseCode();
            if (responseCode == 404) {
                System.out.println("Hash FAILED: Block hash not found on blockchain. Page does not exist.");
                return;
            } else if (responseCode != 200) {
                System.out.println("Hash FAILED: Unexpected response from blockchain node: HTTP " + responseCode);
                return;
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            data = in.readLine();
            in.close();
        } catch (IOException e) {
            System.out.println("Connection failure. Hash not validated.");
            return;
        }

        Gson gson = new Gson();
        JsonObject body = gson.fromJson(data, JsonObject.class);
        long timestamp;
        try {
            if (body == null || !body.has("timestamp")) {
                System.out.println("Hash FAILED: No timestamp in response. Hash may not be a real confirmed block.");
                return;
            }

            timestamp = body.get("timestamp").getAsLong();

            if (timestamp < 0) {
                System.out.println("Hash FAILED: Invalid timestamp: " + timestamp);
                return;
            }

            ZonedDateTime blockTime = Instant.ofEpochSecond(timestamp).atZone(ZoneId.systemDefault());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss z");

            System.out.println("Hash Timestamp: " + blockTime.format(formatter));


        } catch (Exception e) {
            System.out.println("Hash FAILED! " + data);
            return;
        }
    }
}