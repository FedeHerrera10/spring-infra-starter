package com.fedeherrera.infra.service;

import com.fedeherrera.infra.config.GoogleAuthProperties;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GoogleTokenVerifierService {

    private final GoogleAuthProperties properties;

    public GoogleTokenVerifierService(GoogleAuthProperties properties) {
        this.properties = properties;
    }

    public GoogleIdToken.Payload verify(String idTokenString) {
        try {
            if (idTokenString == null || idTokenString.trim().isEmpty()) {
                throw new BadCredentialsException("El token no puede estar vacío");
            }

            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(),
                    JacksonFactory.getDefaultInstance()
            )
            .setAudience(List.of(properties.getId()))
            .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            
            if (idToken == null) {
                throw new BadCredentialsException("No se pudo verificar el token de Google");
            }

            GoogleIdToken.Payload payload = idToken.getPayload();
            
            // Validamos que el Client ID del token coincida con el que tenemos en nuestro .env
            if (!payload.getAudienceAsList().contains(properties.getId())) {
                throw new BadCredentialsException("El token no pertenece a este Cliente ID");
            }

            return payload;

        } catch (Exception e) {
            throw new BadCredentialsException("Error crítico verificando token de Google: " + e.getMessage());
        }
    }
}