package com.springboot.app.oauth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableFeignClients
@EnableEurekaClient
@SpringBootApplication
public class SpringbootServicioOauthApplication implements CommandLineRunner {

  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public SpringbootServicioOauthApplication(
      BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  public static void main(String[] args) {
    SpringApplication.run(SpringbootServicioOauthApplication.class, args);
  }

  @Override
  public void run(String... args) throws Exception {
    String password = "12345";
    for (int i = 0; i < 4; i++) {
      String passwordBcrypt = bCryptPasswordEncoder.encode(password);
      System.out.println(passwordBcrypt);
    }
  }
}
