package oidc.implementation.security;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.MendixRuntimeException;
import oidc.implementation.common.Constants;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public final class SelfSignedCertificateGenerator {

    private static final ILogNode log = Core.getLogger(Constants.LOG_NODE);

    public static class CertificateHolder {
        private final X509Certificate certificate;

        public CertificateHolder(X509Certificate certificate) {
            this.certificate = certificate;
        }

        public String getCertificateThumbnail() throws NoSuchAlgorithmException, CertificateEncodingException {
            return calculateThumbprint(certificate.getEncoded());
        }

        public String serializeCertificateToPEM() {
            try (StringWriter stringWriter = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
                pemWriter.writeObject(certificate);
                pemWriter.flush();
                return stringWriter.toString();

            } catch (IOException e) {
                log.error("An error occurred during encoding the certificate.", e);
                throw new MendixRuntimeException("An error occurred during encoding the certificate.", e);
            }
        }

        private String calculateThumbprint(byte[] certBytes) throws NoSuchAlgorithmException {

            final MessageDigest digest = MessageDigest.getInstance("SHA-1");
            final byte[] thumbprintBytes = digest.digest(certBytes);

            final StringBuilder thumbprintBuilder = new StringBuilder();
            for (byte b : thumbprintBytes) {
                thumbprintBuilder.append(String.format("%02X", b));
            }

            return thumbprintBuilder.toString();
        }

        public X509Certificate getCertificate() {
            return certificate;
        }
    }
}