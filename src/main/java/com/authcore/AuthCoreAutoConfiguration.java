package com.authcore;

import com.authcore.context.OAuth2UserProcessor;
import com.authcore.filter.JwtAuthenticationFilter;
import com.authcore.handler.OAuth2SuccessHandler;
import com.authcore.property.AuthProperties;
import com.authcore.context.AuthUserProvider;
import com.authcore.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(AuthProperties.class)
public class AuthCoreAutoConfiguration {

    private final AuthProperties authProperties;

    public AuthCoreAutoConfiguration(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService() {
        return new JwtService(authProperties);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService, AuthUserProvider authUserProvider,@Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        return new JwtAuthenticationFilter(jwtService, authUserProvider, exceptionResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = "auth-core.enable-oauth", havingValue = "true", matchIfMissing = false)
    public OAuth2SuccessHandler oAuth2SuccessHandler(JwtService jwtService, OAuth2UserProcessor processor, AuthProperties properties) {
        return new OAuth2SuccessHandler(jwtService, processor, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtFilter,
                                                   @Autowired(required = false) OAuth2SuccessHandler successHandler) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(authProperties.getWhitelist().toArray(new String[0])).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        if (successHandler != null && authProperties.isEnableOauth()) {
            http.oauth2Login(oauth2 -> oauth2.successHandler(successHandler));
        }

        return http.build();
    }
}
