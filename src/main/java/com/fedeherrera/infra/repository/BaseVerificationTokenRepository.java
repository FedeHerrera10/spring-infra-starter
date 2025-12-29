package com.fedeherrera.infra.repository;

import com.fedeherrera.infra.entity.BaseVerificationToken;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

@NoRepositoryBean // <--- Fundamental: le dice a Spring que no cree un bean de esto
public interface BaseVerificationTokenRepository<T extends BaseVerificationToken> extends JpaRepository<T, Long> {

    Optional<T> findByToken(String token);

    // Nota: deleteByUserId fallará aquí porque BaseVerificationToken no tiene el campo 'user'
    // Es mejor manejar el borrado por token o mover la lógica de ID al proyecto final
    void deleteByToken(String token);
}