package com.fedeherrera.infra.dto;  

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class AdminCreateUserRequest {

    @NotBlank
    private String username;

    @Email
    private String email;

    @NotBlank
    private String password;

    private String firstName;
    private String lastName;

    @NotEmpty
    private Set<String> roles;
}
