package com.fedeherrera.infra.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    // Almacena los "baldes" de peticiones por IP y límite
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    /**
     * Resuelve o crea un balde para una IP específica.
     * @param ip La dirección IP del cliente.
     * @param limit Cantidad de peticiones permitidas por minuto.
     */
    public Bucket resolveBucket(String ip, int limit) {
        String key = ip + "-" + limit;
        return cache.computeIfAbsent(key, k -> createNewBucket(limit));
    }

    private Bucket createNewBucket(int limit) {
        // Refill.intervally(limit, 1 min) significa que el balde se llena 
        // completamente cada minuto con la cantidad del límite.
        return Bucket.builder()
                .addLimit(Bandwidth.classic(limit, Refill.intervally(limit, Duration.ofMinutes(1))))
                .build();
    }
}