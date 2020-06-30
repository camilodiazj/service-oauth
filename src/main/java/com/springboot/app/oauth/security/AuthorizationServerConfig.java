package com.springboot.app.oauth.security;

import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@RefreshScope
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  private final Environment environment;
  private final BCryptPasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final InfoAdicionalToken infoAdicionalToken;

  public AuthorizationServerConfig(BCryptPasswordEncoder bCryptPasswordEncoder,
      AuthenticationManager authenticationManager, InfoAdicionalToken infoAdicionalToken,
      Environment environment) {
    this.passwordEncoder = bCryptPasswordEncoder;
    this.authenticationManager = authenticationManager;
    this.infoAdicionalToken = infoAdicionalToken;
    this.environment = environment;
  }

  //Permisos que van a tener los endpoins para generar el token y validar el token.
  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.tokenKeyAccess("permitAll") //endpoint de autenticación: Por ese debe ser público.
        .checkTokenAccess("isAuthenticated()");
  }

  //Configurar el registro de las aplicaciones Cliente: Se autentica la aplicación frontent y el usuario.
  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.inMemory()
        .withClient(environment.getProperty("config.security.oauth.client.id"))
        .secret(environment.getProperty("config.security.oauth.client.secret"))
        .scopes("read", "write")
        .authorizedGrantTypes("password", "refresh_token")
        .accessTokenValiditySeconds(3600)
        .refreshTokenValiditySeconds(3600);

  }

  //Esta configuración esta relacionada al endpoint de outh2 del servidior de autorización /oauth/token
  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

    TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
    tokenEnhancerChain.setTokenEnhancers(Arrays.asList(infoAdicionalToken, accessTokenConverter()));

    endpoints.authenticationManager(authenticationManager)
        .tokenStore(tokenStore())
        .accessTokenConverter(accessTokenConverter())
        .tokenEnhancer(tokenEnhancerChain);
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
    jwtAccessTokenConverter.setSigningKey(environment.getProperty("config.security.oauth.jwk.key"));
    return jwtAccessTokenConverter;
  }


}
