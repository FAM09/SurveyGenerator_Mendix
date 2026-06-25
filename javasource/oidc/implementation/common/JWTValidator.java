package oidc.implementation.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import oidc.proxies.constants.Constants;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Set;

public final class JWTValidator {


    public static JWTClaimsSet validate(final String encodedJWT,
                                        final String issuer,
                                        final Set<String> audience,
                                        final String jwksEndpointURL,
                                        final int maxClockSkew) throws MalformedURLException, BadJOSEException, ParseException, JOSEException {

        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(
                Constants.getJWKConnectTimeout().intValue(),
                Constants.getJWKReadTimeout().intValue()
        );

        final JWKSource<SecurityContext> jwsKeySource = JWKSourceBuilder.create(new URL(jwksEndpointURL), resourceRetriever).build();
        final JWTClaimsSet exactMatchJWTClaimsSet = new JWTClaimsSet.Builder().issuer(issuer).build();
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        final DefaultJWTClaimsVerifier<SecurityContext> jwtClaimsVerifier = new DefaultJWTClaimsVerifier<>(audience, exactMatchJWTClaimsSet, null, null);
        jwtClaimsVerifier.setMaxClockSkew(maxClockSkew);


        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwsKeySource));
        jwtProcessor.setJWTClaimsSetVerifier(jwtClaimsVerifier);

        return jwtProcessor.process(encodedJWT, null);
    }


}
