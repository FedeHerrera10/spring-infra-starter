package com.fedeherrera.infra.repository;

import com.fedeherrera.infra.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);

    @Query(value = "SELECT COUNT(*) > 0 FROM user_roles WHERE role_id = :roleId", nativeQuery = true)
boolean existsInUserRoles(@Param("roleId") Long roleId);
    
}