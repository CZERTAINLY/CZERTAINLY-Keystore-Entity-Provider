package com.czertainly.provider.entity.keystore.command;

public class KeytoolCommand {

    public static String prepareKeytoolListCommand(String keystorePath, String keystoreType, String keystorePassword) {
        return "keytool -list -rfc" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword;
    }

    public static String prepareKeytoolPushCertificateCommand(String keystorePath, String keystoreType, String keystorePassword, String certificateFilePath, String alias) {
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
        return "keytool -certreq" +
                " -keystore " + keystorePath +
                " -storetype " + keystoreType +
                " -storepass " + keystorePassword +
                " -alias " + alias +
                " -sigalg " + sigalg +
                " -file " + csrFilePath;
    }
}
