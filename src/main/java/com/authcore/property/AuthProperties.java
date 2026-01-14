package com.authcore.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "auth-core") // yml dosyasındaki "auth-core" altındaki verileri buraya eşler.
public class AuthProperties {

    /**
     * JWT imzalamak için kullanılacak gizli anahtar.
     * En az 256 bit (32 karakter) olmalı.
     */
    private String secretKey;

    /**
     * Token geçerlilik süresi (milisaniye cinsinden).
     * Örn: 3600000 (1 saat)
     */
    private long expirationMs;

    /**
     * Refresh token geçerlilik süresi (Opsiyonel, şimdilik dursun).
     */
    private long refreshExpirationMs;

    /**
     * Token'ın önüne eklenecek prefix (Genelde "Bearer " olur).
     */
    private String tokenPrefix = "Bearer ";

    /**
     * Token'ın hangi header'da taşınacağı (Genelde "Authorization").
     */
    private String headerString = "Authorization";

    /**
     * Login gerektirmeyen (herkese açık) URL listesi.
     * Örn: /auth/login, /auth/register, /swagger-ui/**
     */
    private List<String> whitelist = new ArrayList<>();

    private boolean enableOauth = false;

    private String oAuth2RedirectUri;
}
