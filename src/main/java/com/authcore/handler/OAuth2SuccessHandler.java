package com.authcore.handler;

import com.authcore.context.OAuth2UserProcessor;
import com.authcore.property.AuthProperties;
import com.authcore.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final OAuth2UserProcessor oAuth2UserProcessor;
    private final AuthProperties authProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        String providerId = oauthToken.getAuthorizedClientRegistrationId();

        UserDetails userDetails = oAuth2UserProcessor.process(oauthToken.getPrincipal(), providerId);

        String token = jwtService.generateToken(userDetails);

        String targetUrl = UriComponentsBuilder.fromUriString(authProperties.getOAuth2RedirectUri())
                .queryParam("token", token)
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
