package com.czertainly.provider.entity.keystore.command;

public class KeytoolCommand {

    public static String prepareKeytoolListCommand(String keystorePath, String keystoreType, String keystorePassword) {
        return "keytool -list -rfc" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword;
    }

    public static String prepareKeytoolDetailCommand(String keystorePath, String keystoreType, String keystorePassword, String alias) {
        return "keytool -list -rfc" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias;
    }

    public static String prepareKeytoolPushCertificateCommand(String keystorePath, String keystoreType, String keystorePassword, String certificateFilePath, String alias) {
        if (alias.startsWith("pqc-")) {
            return "keytool -importcert" +
                    " -keystore " + keystorePath +
                    " -storetype " + keystoreType +
                    " -storepass " + keystorePassword +
                    " -alias " + alias +
                    " -file " + certificateFilePath +
                    " -providerpath /home/testssh/bcprov-jdk18on-176.jar -provider org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider" +
                    " -trustcacerts -noprompt";
        }
        return "keytool -importcert" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias +
                " -file " + certificateFilePath +
                " -trustcacerts -noprompt";
    }

    public static String prepareKeytoolRemoveCertificateCommand(String keystorePath, String keystoreType, String keystorePassword, String alias) {
        return "keytool -delete" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias;
    }

    public static String prepareKeytoolGenerateKeyPairCommand(String keystorePath, String keystoreType, String keystorePassword,
                                                              String alias, String keyalg, String keysize, String sigalg, String dname) {
        if (alias.startsWith("pqc-")) {
            return "keytool -genkeypair" +
                    " -keystore " + keystorePath +
                    " -storetype " + keystoreType +
                    " -storepass " + keystorePassword +
                    " -alias " + alias +
                    " -keyalg " + keyalg +
                    " -sigalg " + sigalg +
                    " -keypass " + keystorePassword +
                    " -providerpath /home/testssh/bcprov-jdk18on-176.jar -provider org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider" +
                    " -dname '" + dname + "'";
        }
        return "keytool -genkeypair" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias +
                " -keyalg " + keyalg +
                " -keysize " + keysize +
                " -sigalg " + sigalg +
                " -keypass " + keystorePassword +
                " -dname '" + dname + "'";
    }

    public static String prepareKeytoolGenerateCsrCommand(String keystorePath, String keystoreType, String keystorePassword,
                                                              String alias, String sigalg, String csrFilePath) {
        if (alias.startsWith("pqc-")) {
            return "keytool -certreq" +
                    " -keystore " + keystorePath +
                    " -storetype " + keystoreType +
                    " -storepass " + keystorePassword +
                    " -alias " + alias +
                    " -sigalg " + sigalg +
                    " -providerpath /home/testssh/bcprov-jdk18on-176.jar -provider org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider" +
                    " -file " + csrFilePath;
        }
        return "keytool -certreq" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias +
                " -sigalg " + sigalg +
                " -file " + csrFilePath;
    }
}
