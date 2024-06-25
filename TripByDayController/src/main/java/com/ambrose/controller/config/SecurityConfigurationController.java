package com.ambrose.controller.config;



import com.ambrose.repository.entities.enums.Role;
import com.ambrose.service.config.JwtAuthenticationFilter;
import com.ambrose.service.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = false, jsr250Enabled = false)
public class SecurityConfigurationController implements WebMvcConfigurer {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final UserService userService;
  @Bean
  public SecurityFilterChain securityFilterChainController(HttpSecurity http) throws Exception{
    http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(request -> request.requestMatchers("api/v1/auth/**",
                "/swagger-ui/**",
                "/swagger-ui.html",
                "swagger-resources/**",
                "/v3/api-docs/**",
                "webjars/**",
                "/login/oauth2/**",
                "oauth2/**")
            .permitAll()
            //.requestMatchers("/api/v1/auth/signingoogle").authenticated()
            .requestMatchers("/api/v1/admin/**").hasAnyAuthority(Role.ADMIN.name())
            .requestMatchers("/api/v1/user/**").hasAnyAuthority(Role.CUSTOMER.name())
            .requestMatchers("/api/v1/gallery/**").hasAnyAuthority(Role.CUSTOMER.name())
            .requestMatchers("/api/v1/city/**").hasAnyAuthority(Role.ADMIN.name())
            .anyRequest().authenticated())

        .oauth2Login(oauth2 -> oauth2
            .defaultSuccessUrl("/api/v1/auth/signingoogle", true))

        //      .oauth2Login(Customizer.withDefaults())
        //      .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.NEVER))
        .authenticationProvider(authenticationProvider()).addFilterBefore(
            jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class
        );
    http.exceptionHandling(exception -> exception
        .authenticationEntryPoint(authenticationEntryPoint())
        .accessDeniedHandler(accessDeniedHandler()));
    return http.build();
  }

  private AuthenticationEntryPoint authenticationEntryPoint() {
    return new HttpStatusEntryPoint(HttpStatus.FORBIDDEN);
  }

  private AccessDeniedHandler accessDeniedHandler() {
    AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
    accessDeniedHandler.setErrorPage("/403");
    return accessDeniedHandler;
  }
  @Bean
  public AuthenticationProvider authenticationProvider(){
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userService.userDetailsService());
    authenticationProvider.setPasswordEncoder(passwordEncoder());
    return authenticationProvider;
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }



  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/**")
        .allowedOrigins("*")
        .allowedMethods("GET,POST,PATCH,PUT,DELETE,OPTIONS,HEAD")
        .allowedHeaders("*")
        .exposedHeaders("X-Get-Header");
  }

}
