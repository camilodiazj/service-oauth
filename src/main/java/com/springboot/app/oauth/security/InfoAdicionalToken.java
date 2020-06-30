package com.springboot.app.oauth.security;

import com.kmilo.commons.users.springbootusers.models.entity.Usuario;
import com.springboot.app.oauth.services.UsuarioService;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

@Component
public class InfoAdicionalToken implements TokenEnhancer {

  private final UsuarioService usuarioService;

  public InfoAdicionalToken(UsuarioService usuarioService) {
    this.usuarioService = usuarioService;
  }

  //Metodo para potenciar el token
  @Override
  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
      OAuth2Authentication authentication) {
    Map<String, Object> information = new HashMap<>();

    Usuario usuario = usuarioService.findByUsername(authentication.getName());
    information.put("nombre", usuario.getNombre());
    information.put("apellido", usuario.getApellido());
    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(information);

    return accessToken;
  }
}
