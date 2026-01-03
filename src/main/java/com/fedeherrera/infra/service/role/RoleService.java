package com.fedeherrera.infra.service.role;

import com.fedeherrera.infra.entity.Role;

import java.util.List;
import java.util.Optional;

public interface RoleService {

    Optional<Role> findByName(String name);
    
    List<Role> findAll();

    Role save(Role role);
    
    void deleteById(Long id);

    
    
    
}
