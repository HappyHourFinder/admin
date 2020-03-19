package com.mathieuaime.hhf.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import java.util.UUID;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private final AdminServerProperties adminServer;

  public WebSecurityConfig(AdminServerProperties adminServer) {
    this.adminServer = adminServer;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    successHandler.setTargetUrlParameter("redirectTo");

    String adminPath = this.adminServer.getContextPath();
    successHandler.setDefaultTargetUrl(adminPath + "/");

    http
        .authorizeRequests()
        .antMatchers(adminPath + "/assets/**").permitAll()
        .antMatchers(adminPath + "/login").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage(adminPath + "/login")
        .successHandler(successHandler)
        .and()
        .logout()
        .logoutUrl(adminPath + "/logout")
        .and()
        .httpBasic()
        .and()
        .csrf()
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .ignoringRequestMatchers(
            new AntPathRequestMatcher(adminPath + "/instances", HttpMethod.POST.toString()),
            new AntPathRequestMatcher(adminPath + "/instances/*", HttpMethod.DELETE.toString()),
            new AntPathRequestMatcher(adminPath + "/actuator/**"))
        .and()
        .rememberMe()
        .key(UUID.randomUUID().toString())
        .tokenValiditySeconds(1209600);
  }
}