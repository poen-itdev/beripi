package com.poen.beripi.utils;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;

@Component
public class JWTUtil {
    
    @Value("${jwt.secret}")
    private String secretKeyString;
    
    @Value("${jwt.access-token-expiry}")
    private Long accessTokenExpiresIn;
    
    @Value("${jwt.refresh-token-expiry}")
    private Long refreshTokenExpiresIn;
    
    private SecretKey secretKey;

     @PostConstruct
    public void init() {
        this.secretKey = new SecretKeySpec(
            secretKeyString.getBytes(StandardCharsets.UTF_8), 
            Jwts.SIG.HS256.key().build().getAlgorithm()
        );
    }

    // JWT 클레임 memberId 파싱
    public String getMemberId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("sub", String.class);
    }

    // Jwt 클레임 role 파싱
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // JWT 유효 여부(위조, 시간, Access/Refresh 여부)
    public Boolean isValid(String token, Boolean isAccess) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String type = claims.get("type", String.class);
            if (type == null) return false;

            if (isAccess && !type.equals("access")) return false;
            if (!isAccess && !type.equals("refresh")) return false;

            return true;

        } catch(JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // JWT(Access/Refresh) 생성
    public String createJwt(String memberId, String role, Boolean isAccess) {
        long now = System.currentTimeMillis();
        long expiry = isAccess ? accessTokenExpiresIn : refreshTokenExpiresIn;
        String type = isAccess ? "access" : "refresh";

        return Jwts.builder()
            .claim("sub", memberId) // 아이디
            .claim("role", role) // role
            .claim("type", type) // access 인지 refresh 인지
            .issuedAt(new Date(now)) // jwt 발급시간 
            .expiration(new Date(now + expiry)) // jwt 생명주기
            .signWith(secretKey) 
            .compact();
    }
}
