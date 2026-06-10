package com.authcore.filter;

import com.authcore.context.AuthUserProvider;
import com.authcore.property.AuthProperties;
import com.authcore.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuthUserProvider authUserProvider;
    private final HandlerExceptionResolver exceptionResolver;
    private final AuthProperties authProperties;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt;
            final String identifier;

            jwt = authHeader.substring(7);

            identifier = jwtService.extractIdentifier(jwt);

            if (identifier != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.authUserProvider.loadUserByIdentifier(identifier);

                if (userDetails!=null && jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("User authenticated via JWT: {}", identifier);
                }
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("JWT Filter Error: {}", e.getMessage());
            exceptionResolver.resolveException(request, response, null, e);
        }
    }

    @Override
    protected boolean shouldNotFilter(@org.jspecify.annotations.NonNull HttpServletRequest request) throws ServletException {
        AntPathMatcher pathMatcher = new AntPathMatcher();
        String path = request.getServletPath();

        String[] patterns = new String[0];
        if (authProperties != null && authProperties.getWhitelist() != null) {
            patterns = authProperties.getWhitelist().toArray(new String[0]);
        }

        boolean shouldNotFilter = Arrays.stream(patterns)
                .anyMatch(pattern -> pathMatcher.match(pattern, path));

        if (shouldNotFilter) {
            log.trace("Skipping JWT filter for public path: {}", path);
        }

        return shouldNotFilter;
    }
}
