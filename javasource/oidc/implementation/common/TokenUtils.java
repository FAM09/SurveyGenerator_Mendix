package oidc.implementation.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;

public final class TokenUtils {


    public static JWT parseJWTFromString(final String encodedJWT) throws ParseException {
        if (encodedJWT == null || encodedJWT.trim().isEmpty()) {
            throw new IllegalArgumentException("encodedJWT cannot be empty");
        }
        return JWTParser.parse(encodedJWT);
    }

    public static String getClaimValueAsString(final String encodedJWT, final String claimName) throws ParseException {
        return parseJWTFromString(encodedJWT).getJWTClaimsSet().getStringClaim(claimName);
    }

    public static List<String> getClaimValueAsStringArray(final String encodedJWT, final String claimName) throws ParseException {
        return JSONObjectUtils.getStringList(parseJWTFromString(encodedJWT).getJWTClaimsSet().getClaims(), claimName);
    }


    public static String getDecodedPayload(final String encodedJWT) throws ParseException {
        JWT jwt = parseJWTFromString(encodedJWT);
        return jwt.getJWTClaimsSet().toString(true);
    }


    public static String createSignedJWTString(final JWSAlgorithm algorithm, final JWK jwk,final List<String> audiances ,final oidc.proxies.JWT jwt) throws JOSEException {

        SignedJWT signedJWT = createSignedJWT(jwt.getkid(), algorithm, getJWSSigner(algorithm,jwk), generateJWTClaimsSet(audiances, jwt));
        return signedJWT.serialize();
    }

    public static SignedJWT createSignedJWT(final String kid,final JWSAlgorithm algorithm,final JWSSigner signer, final JWTClaimsSet claimsSet) throws JOSEException {
        final JWSHeader header = new JWSHeader
                .Builder(algorithm)
                .keyID(kid)
                .build();
        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }


    private static JWTClaimsSet generateJWTClaimsSet(final List<String> auds,final oidc.proxies.JWT jwt) {
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        if (jwt.getexp() != null) builder.expirationTime(jwt.getexp());
        if (jwt.getiss() != null && !jwt.getiss().isBlank()) builder.issuer(jwt.getiss());
        if (jwt.getjti() != null && !jwt.getjti().isBlank()) builder.jwtID(jwt.getjti());
        if (jwt.getsub() != null && !jwt.getsub().isBlank()) builder.subject(jwt.getsub());
        if (!auds.isEmpty()) builder.audience(auds);
        return builder.build();
    }


    private static JWSSigner getJWSSigner(final JWSAlgorithm jwsAlgorithm, final JWK jwkObj) throws JOSEException {

        if (jwkObj instanceof ECKey && JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
            return new ECDSASigner((ECKey) jwkObj);
        } else if (jwkObj instanceof RSAKey && JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
            return new RSASSASigner((RSAKey) jwkObj);
        } else {
            throw new JOSEException("Unsupported JWK type or algorithm: " + jwkObj.getKeyType() + ", " + jwsAlgorithm);
        }
    }






}