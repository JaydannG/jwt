package com.grossman.security.config;

import java.util.function.Function;
import java.security.Key;
import java.util.HashMap;
import java.util.Date;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    private static final String SECRET_KEY = "2dd20424f6b625b06db596de69bed262dd0da16855fecf9fe2d7bda1c9deec2c6607b4de0bfa7f99a5d8d2e0b2dbd75b23ca359e679c39957a9e51b114b421dd1e147a51b1cad50e457e9ac2c353dc4a230dc5b22a315672173b0d3d65dbfab185c2ac45cc41e68bcf84b1c7b619c37c6d492d9827fe4597efe59632d50d0a9077d806724a230e972e89877c93299f5383d0d709b723e769ed96111e3c0475742cd7f50e5029662d1700520ff7f6dbaca961808df88286b587c58b66cc5a2af8dc5bf40cf2948b7bcf3e6bea2249cc677093c1976f5f3dd349076134c6846b6b75667e33b5dc9df923faa5231572b3961294eda3cb38e74b6fea8a192b617a07";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis())).setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)).signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
