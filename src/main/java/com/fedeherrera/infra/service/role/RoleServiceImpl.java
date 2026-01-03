package com.fedeherrera.infra.service.role;

import com.fedeherrera.infra.entity.Role;
import com.fedeherrera.infra.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Optional<Role> findByName(String name) {
        return roleRepository.findByName(name);
    }

    @Override
    public List<Role> findAll() {
        return roleRepository.findAll();
    }

    @Override
    
    @Transactional
    public Role save(Role role) {
        
        if (role.getName() == null || role.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be null or empty");
        }

        Optional<Role> existingRole = roleRepository.findByName(role.getName());
        if (!existingRole.isPresent()) {
            throw new IllegalArgumentException("Role with name " + role.getName() + " already exists");
        }
        
        return roleRepository.save(role);
    }

    @Override
    @Transactional
    public void deleteById(Long id) {
        Role role = roleRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Role not found"));
        
        if (roleRepository.existsInUserRoles(id)) {
            throw new IllegalStateException("Cannot delete role that is assigned to users");
        }
        
        roleRepository.delete(role);
    }

    
}
