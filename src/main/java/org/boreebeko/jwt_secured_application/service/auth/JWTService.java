package org.boreebeko.jwt_secured_application.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.domain.SecurityUser;
import org.boreebeko.jwt_secured_application.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JWTService {

    @Value("${token.signing.access.key}")
    private String accessTokenSigningKey;

    @Value("${token.signing.refresh.key}")
    private String refreshTokenSigningKey;

    public enum TokenType {
        ACCESS_TOKEN, REFRESH_TOKEN
    }

    public String extractUsername(String token, TokenType tokenType) throws AuthenticationException {
        return extractClaim(token, Claims::getSubject, tokenType);
    }

    public String generateToken(UserDetails userDetails, TokenType tokenType) {
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof SecurityUser securityUser) {
            claims.put("role", securityUser.getAuthorities());
        }
        return generateToken(claims, userDetails, tokenType);
    }

    public boolean isTokenValid(String token, UserDetails userDetails, TokenType tokenType)
            throws AuthenticationException {

        final String username = extractUsername(token, tokenType);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token, tokenType);
    }

    private boolean isTokenExpired(String token, TokenType tokenType) throws AuthenticationException {
        return extractExpiration(token, tokenType).before(new Date(System.currentTimeMillis()));
    }

    private Date extractExpiration(String token, TokenType tokenType) throws AuthenticationException {
        return extractClaim(token, Claims::getExpiration, tokenType);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, TokenType tokenType) {
        return Jwts
                .builder()
                .subject(userDetails.getUsername())
                .claims(extraClaims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(
                        switch (tokenType) {
                            case ACCESS_TOKEN -> new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(3));
                            case REFRESH_TOKEN -> new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5));
                        }
                )
                .signWith(getSigningKey(tokenType))
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver, TokenType tokenType) throws AuthenticationException {
        final Claims claims = extractAllClaims(token, tokenType);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, TokenType tokenType) throws AuthenticationException {
        try {
            return Jwts
                    .parser()
                    .verifyWith(getSigningKey(tokenType))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException exception) {
            System.out.println(token);
            exception.printStackTrace();
            throw new AuthenticationException();
        }
    }

    private SecretKey getSigningKey(TokenType tokenType) {

        SecretKey key = null;

        switch (tokenType) {
            case ACCESS_TOKEN -> {
                key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSigningKey));
            }
            case REFRESH_TOKEN -> {
                key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSigningKey));
            }
        }

        return key;
    }
}
