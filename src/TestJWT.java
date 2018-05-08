
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JoseException;


import java.util.Arrays;
import java.util.List;


public class TestJWT {


    public static void testJWT() throws JoseException, MalformedClaimException {


        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        rsaJsonWebKey.setKeyId("k1");

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("Issuer");
        claims.setAudience("Audience");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("Subject");
        claims.setClaim("email", "mail@argotec.es");
        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
        claims.setStringListClaim("groups", groups);

        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(claims.toJson());

        jws.setKey(rsaJsonWebKey.getPrivateKey());

        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyType());

        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);

        String jwt = jws.getCompactSerialization();

        System.out.println("JWT: " + jwt);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer("Issuer")
                .setExpectedAudience("Audience")
                .setVerificationKey(rsaJsonWebKey.getKey())
                .setJwsAlgorithmConstraints(
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                AlgorithmIdentifiers.RSA_USING_SHA512))
                .build();
        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            System.out.println("JWT validation succeeded " + jwtClaims);
        } catch (InvalidJwtException e) {

            System.out.println("Invalid JWT! " + e);

            if (e.hasExpired()) {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                System.out.println();
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }
        }
    }
}

