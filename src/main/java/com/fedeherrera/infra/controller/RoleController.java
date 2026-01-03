package com.fedeherrera.infra.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PutMapping;

import com.fedeherrera.infra.entity.Role;
import com.fedeherrera.infra.service.role.RoleService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;

/**
 * Controlador REST para la gestión de roles en el sistema.
 * Permite realizar operaciones CRUD sobre los roles de usuario.
 */
@Tag(name = "Roles", description = "API para la gestión de roles del sistema")
@RestController
@RequestMapping("/auth/role")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    /**
     * Obtiene todos los roles disponibles en el sistema.
     * 
     * @return Lista de todos los roles
     */
    @Operation(
        summary = "Obtener todos los roles",
        description = "Retorna una lista de todos los roles registrados en el sistema"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Lista de roles obtenida exitosamente",
            content = @Content(mediaType = "application/json", 
                             schema = @Schema(implementation = Role.class))
        )
    })
    @GetMapping
    public List<Role> getAllRoles() {
        return roleService.findAll();
    }

    /**
     * Obtiene un rol por su nombre.
     * 
     * @param name Nombre del rol a buscar
     * @return El rol encontrado o null si no existe
     */
    @Operation(
        summary = "Buscar rol por nombre",
        description = "Retorna un rol específico basado en su nombre"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Rol encontrado exitosamente",
            content = @Content(mediaType = "application/json", 
                             schema = @Schema(implementation = Role.class))
        ),
        @ApiResponse(
            responseCode = "404", 
            description = "Rol no encontrado",
            content = @Content
        )
    })
    @GetMapping("/{name}")
    public Role getRoleByName(
        @Parameter(description = "Nombre del rol a buscar", required = true)
        @PathVariable String name
    ) {
        return roleService.findByName(name).orElse(null);
    }

    /**
     * Crea un nuevo rol en el sistema.
     * 
     * @param role Objeto Role con los datos del nuevo rol
     * @return El rol creado
     */
    @Operation(
        summary = "Crear un nuevo rol",
        description = "Crea un nuevo rol en el sistema"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "201", 
            description = "Rol creado exitosamente",
            content = @Content(mediaType = "application/json", 
                             schema = @Schema(implementation = Role.class))
        ),
        @ApiResponse(
            responseCode = "400", 
            description = "Datos del rol inválidos",
            content = @Content
        )
    })
    @PostMapping
    public Role createRole(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Objeto Role que será creado",
            required = true,
            content = @Content(schema = @Schema(implementation = Role.class))
        )
        @RequestBody Role role
    ) {
        return roleService.save(role);
    }

    /**
     * Actualiza un rol existente.
     * 
     * @param id Identificador del rol a actualizar
     * @param role Nuevos datos del rol
     * @return El rol actualizado
     */
    @Operation(
        summary = "Actualizar un rol existente",
        description = "Actualiza los datos de un rol existente"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Rol actualizado exitosamente",
            content = @Content(mediaType = "application/json", 
                             schema = @Schema(implementation = Role.class))
        ),
        @ApiResponse(
            responseCode = "404", 
            description = "Rol no encontrado",
            content = @Content
        )
    })
    @PutMapping("/{id}")
    public Role updateRole(
        @Parameter(description = "ID del rol a actualizar", required = true)
        @PathVariable Long id,
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Objeto Role con los datos actualizados",
            required = true,
            content = @Content(schema = @Schema(implementation = Role.class))
        )
        @RequestBody Role role
    ) {
        role.setId(id);
        return roleService.save(role);
    }

    /**
     * Elimina un rol del sistema.
     * 
     * @param id Identificador del rol a eliminar
     * @return Respuesta sin contenido
     */
    @Operation(
        summary = "Eliminar un rol",
        description = "Elimina un rol del sistema. No se puede eliminar un rol que esté asignado a usuarios."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "204", 
            description = "Rol eliminado exitosamente",
            content = @Content
        ),
        @ApiResponse(
            responseCode = "404", 
            description = "Rol no encontrado",
            content = @Content
        ),
        @ApiResponse(
            responseCode = "409", 
            description = "No se puede eliminar el rol porque está asignado a usuarios",
            content = @Content
        )
    })
    @DeleteMapping("/{id}")
    public void deleteRole(
        @Parameter(description = "ID del rol a eliminar", required = true)
        @PathVariable Long id
    ) {
        roleService.deleteById(id);
    }
}