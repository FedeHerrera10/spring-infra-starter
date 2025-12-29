package com.fedeherrera.infra.service.role;

import com.fedeherrera.infra.entity.Role;

import java.util.Optional;

public interface RoleService {

    Optional<Role> findByName(String name);
}
