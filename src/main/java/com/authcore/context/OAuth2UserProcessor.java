package com.authcore.context;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Strategy interface for processing OAuth2 users after a successful authentication.
 * <p>
 * Applications using the {@code auth-core} library must implement this interface to define
 * how to map an external {@link OAuth2User} (from providers like Google, GitHub) to the
 * application's local domain user ({@link UserDetails}).
 * </p>
 * <p>
 * This is typically used to load an existing user from the database by email
 * or register a new user if they do not exist.
 * </p>
 *
 * @author AuthCore Library
 */
public interface OAuth2UserProcessor {

    /**
     * Resolves the incoming OAuth2 user to a local application user.
     *
     * @param oauth2User The principal object containing attributes (email, name, picture, etc.)
     * received from the OAuth2 provider.
     * @param providerId The registration ID of the provider (e.g., "google", "github").
     * Useful if you need to handle providers differently.
     * @return The fully populated {@link UserDetails} object required for the Security Context.
     */
    UserDetails process(OAuth2User oauth2User, String providerId);
}
