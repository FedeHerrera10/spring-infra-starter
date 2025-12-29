package com.fedeherrera.infra.service.user;

import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.UserPrincipal;
import com.fedeherrera.infra.repository.BaseUserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl<T extends BaseUser> implements UserDetailsService {

    private final BaseUserRepository<? extends BaseUser> userRepository;

    // AÑADE @Lazy AQUÍ 
    public UserDetailsServiceImpl(@org.springframework.context.annotation.Lazy BaseUserRepository<? extends BaseUser> userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BaseUser user = userRepository.findByUsername(username.toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
        
        return new UserPrincipal(user); 
    }
}