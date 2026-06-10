package com.authcore.service;

import com.authcore.property.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
public class JwtService {

    private final AuthProperties authProperties;
    private Key signInKey;

    public JwtService(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    @PostConstruct
    public void init() {
        String raw = authProperties.getSecretKey();
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("auth-core.secretKey must be provided and non-empty");
        }

        try {
            byte[] keyBytes = Decoders.BASE64.decode(raw);
            this.signInKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            log.debug("Secret is not valid base64, falling back to raw UTF-8 bytes");
            byte[] keyBytes = raw.getBytes(StandardCharsets.UTF_8);
            this.signInKey = Keys.hmacShaKeyFor(keyBytes);
        }
    }

    public String extractIdentifier(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, authProperties.getExpirationMs());
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuer(authProperties.getIssuer())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String identifier = extractIdentifier(token);
        return (identifier.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Token'ı parçalayıp içindeki tüm verilere erişir.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Konfigürasyondaki Secret Key'i şifreleme anahtarına dönüştürür.
     */
    private Key getSignInKey() {
        return this.signInKey;
    }

    public long getRemainingExpirationMillis(String token) {
        try {
            Date expirationDate = extractClaim(token, Claims::getExpiration);
            return Math.max(0,(expirationDate.getTime()-new Date().getTime()));
        } catch (Exception e) {
            return 0;
        }
    }
}
