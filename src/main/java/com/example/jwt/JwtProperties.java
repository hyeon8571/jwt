package com.example.jwt;

public interface JwtProperties {

    String SECRET = "plant";
    int EXPIRATION_TIME = 600000;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}

