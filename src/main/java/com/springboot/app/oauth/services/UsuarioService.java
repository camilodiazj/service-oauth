package com.springboot.app.oauth.services;

import com.kmilo.commons.users.springbootusers.models.entity.Usuario;
import com.springboot.app.oauth.clients.UsuarioFeignClient;
import java.util.Collection;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService implements UserDetailsService {

  private Logger log = LoggerFactory.getLogger(UsuarioService.class);

  private final UsuarioFeignClient client;

  public UsuarioService(UsuarioFeignClient client) {
    this.client = client;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Usuario usuario = client.findByUsername(username);

    if (usuario == null) {
      log.error("Error en el login, no existe el usuario ".concat(username));
      throw new UsernameNotFoundException(
          "Error en el login, no existe el usuario ".concat(username));
    }

    Collection<GrantedAuthority> authorities = usuario.getRoles().stream()
        .map(role -> (GrantedAuthority) role::getNombre)
        .peek(grantedAuthority -> log.info("Role: ".concat(grantedAuthority.getAuthority())))
        .collect(Collectors.toList());

    log.info("Usuario autenticado: ".concat(username));

    return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true,
        true, authorities);
  }
}
