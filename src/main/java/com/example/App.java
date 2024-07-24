package com.example;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class App {
    public static void main(String[] args) {
//        Config config = new Config("/home/reidel/project/javatesting/privatekey.asc");
        Config config = new Config("/home/reidel/project/javatesting/plain_text.gpg");
        App app = new App(config);

        try {
            PGPSecretKeyRingCollection collection = app.getPgpSecurityCollection();
            System.out.println("PGP Secret Key Ring Collection successfully loaded.");
        } catch (IllegalStateException e) {
            System.err.println("Failed to load PGP Secret Key Ring Collection: " + e.getMessage());
        }
    }

    private Config config;

    public App(Config config) {
        this.config = config;
    }

    private PGPSecretKeyRingCollection getPgpSecurityCollection() {
        InputStream keyIn;
        try {
            keyIn = new BufferedInputStream(new FileInputStream(config.getPrivateKeyLocation()));
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("PGP private key file not found. file: " + config.getPrivateKeyLocation(), e);
        }

        try {
            return new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new IllegalStateException("Exception in reading PGP security collection ring", e);
        }
    }
}

class Config {
    private String privateKeyLocation;

    public Config(String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation;
    }

    public String getPrivateKeyLocation() {
        return privateKeyLocation;
    }
}
