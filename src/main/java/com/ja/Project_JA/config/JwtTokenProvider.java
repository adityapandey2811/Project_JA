package com.ja.Project_JA.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtTokenProvider {

    private final SecretKey key= Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());


    public String generateToken(Authentication auth){
        return Jwts.builder().setIssuedAt(new Date())
                .setExpiration((new Date(new Date().getTime()+86400000)))
                .claim("email",auth.getName())
                .signWith(key)
                .compact();
    }

}
