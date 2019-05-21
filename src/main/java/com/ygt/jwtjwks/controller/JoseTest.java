package com.ygt.jwtjwks.controller;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

/**
 * @author yanggt
 * @date 19-5-21
 */
public class JoseTest {

    public static void main(String[] args) throws Exception {
        getToken();
    }

    public static void getToken() throws Exception {
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        // 生成RSA 公钥,私钥  用来签署jwt
        // 设置kid
        rsaJsonWebKey.setKeyId("k1");

        // 设置body部分
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("testing@secure.istio.io");
//        claims.setAudience("Audience");
//        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setExpirationTime(NumericDate.fromSeconds(4685989700L));
//        claims.setGeneratedJwtId();
        claims.setIssuedAt(NumericDate.fromSeconds(1532389700L));
//        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("testing@secure.istio.io");
//        claims.setClaim("email","mail@example.com");
//        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
//        claims.setStringListClaim("groups", groups);

        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(claims.toJson());
        // 私钥签署
        jws.setKey(rsaJsonWebKey.getPrivateKey());

        // 设置头部的kid
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setHeader("typ","JWT");

        // 设置签名算法
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        // 签署
        String jwt = jws.getCompactSerialization();
        System.out.println("JWT: " + jwt);

        System.out.println("jwks:"+rsaJsonWebKey.toJson());


        // 验证token
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("testing@secure.istio.io") // whom the JWT needs to have been issued by
//                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try
        {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            System.out.println("JWT validation succeeded! " + jwtClaims);
        }
        catch (InvalidJwtException e)
        {
            // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);

            // Programmatic access to (some) specific reasons for JWT invalidity is also possible
            // should you want different error handling behavior for certain conditions.

            // Whether or not the JWT has expired being one common reason for invalidity
            if (e.hasExpired())
            {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID))
            {
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }
        }

    }

}
