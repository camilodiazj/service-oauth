package com.springboot.app.oauth.services;

import com.kmilo.commons.users.springbootusers.models.entity.Usuario;

public interface IUsuarioService {
  public Usuario findByUsername(String username);
}
