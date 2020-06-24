package com.springboot.app.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  private final BCryptPasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;

  public AuthorizationServerConfig(BCryptPasswordEncoder bCryptPasswordEncoder,
      AuthenticationManager authenticationManager) {
    this.passwordEncoder = bCryptPasswordEncoder;
    this.authenticationManager = authenticationManager;
  }

  //permisos que van a tener los endpoins para generar el token y validar el token
  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.tokenKeyAccess("permitAll") //endpoint de autenticación: Por ese debe ser público.
    .checkTokenAccess("isAuthenticated()");
  }

  //configurar el registro de las aplicaciones Cliente: Se autentica la aplicación fronent y el usuario.
  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.inMemory()
        .withClient("frontendapp")
        .secret(passwordEncoder.encode("12345"))
        .scopes("read","write")
        .authorizedGrantTypes("password", "refresh_token")
    .accessTokenValiditySeconds(3600)
    .refreshTokenValiditySeconds(3600);

  }

  //Esta configuración esta relacionada al endpoint de outh2 del servidior de autorización /oauth/token
  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.authenticationManager(authenticationManager)
        .tokenStore(tokenStore())
    .accessTokenConverter(accessTokenConverter());
  }

  //para poder crear el token y almacenarlo
  @Bean
  public JwtTokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  //Aquí se firma el token y se convierte el token con toda la información
  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setSigningKey("llavePrivada");
    return jwtAccessTokenConverter;
  }



}
