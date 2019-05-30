package com.ygt.jwtjwks.controller;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

/**
 * @author yanggt
 * @date 19-5-21
 */
@RestController
public class JoseController {

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.subject}")
    private String subject;

    RsaJsonWebKey rsaJsonWebKey;

    {
        try {
            rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        } catch (JoseException e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/jwks.json")
    public String jwks(HttpServletRequest request) {
        System.out.println("有请求。。。");
        System.out.println(request.getRemoteAddr());
        // 设置kid
        rsaJsonWebKey.setKeyId(String.valueOf(UUID.randomUUID()));
        System.out.println("jwks:" + rsaJsonWebKey.toJson());
        return rsaJsonWebKey.toJson();
    }

    @GetMapping("/token")
    public String token() {

        // 设置body部分
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setExpirationTime(NumericDate.fromSeconds(4685989700L));
        claims.setIssuedAt(NumericDate.fromSeconds(1532389700L));
        claims.setSubject(subject);
//        claims.setClaim("email","mail@example.com");
//        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
//        claims.setStringListClaim("groups", groups);

        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(claims.toJson());
        // 私钥签署
        jws.setKey(rsaJsonWebKey.getPrivateKey());

        // 设置头部的kid
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setHeader("typ", "JWT");

        // 设置签名算法
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        // 签署
        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (JoseException e) {
            e.printStackTrace();
        }
        System.out.println("JWT: " + jwt);

        return jwt;
    }

    @GetMapping("/validate")
    public void validate(HttpServletRequest request) {
        String token = request.getParameter("token");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // jwt 必须有过期时间
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
//                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            System.out.println("JWT 验证成功! " + jwtClaims);
        } catch (InvalidJwtException e) {
            System.out.println("不可用的 JWT! " + e);

            if (e.hasExpired()) {
                try {
                    System.out.println("JWT 过期 ： " + e.getJwtContext().getJwtClaims().getExpirationTime());
                } catch (MalformedClaimException e1) {
                    e1.printStackTrace();
                }
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                try {
                    System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
                } catch (MalformedClaimException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }
}
