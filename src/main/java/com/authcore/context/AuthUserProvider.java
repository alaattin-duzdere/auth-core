package com.authcore.context;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * <h3>Core Interface for User Retrieval</h3>
 * <p>
 * This interface bridges the auth-core library with your domain user.
 * Instead of forcing a "username", we use a generic <b>identifier</b>.
 * </p>
 *
 * <h3>What is an Identifier?</h3>
 * <p>
 * The identifier is the unique value stored in the JWT "Subject" (sub) field.
 * It can be:
 * <ul>
 * <li>Email (e.g., "user@example.com")</li>
 * <li>User ID (e.g., "1023" or UUID)</li>
 * <li>Username (e.g., "john_doe")</li>
 * </ul>
 * </p>
 *
 * <h3>Example Usage (Email Based):</h3>
 * <pre>
 * {@code
 * @Override
 * public UserDetails loadUserByIdentifier(String identifier) {
 * // Assuming identifier is Email
 * return userRepository.findByEmail(identifier)
 * .orElseThrow(() -> new UsernameNotFoundException("User not found"));
 * }
 * }
 * </pre>
 *
 * <h3>Example Usage (ID Based):</h3>
 * <pre>
 * {@code
 * @Override
 * public UserDetails loadUserByIdentifier(String identifier) {
 * // Assuming identifier is ID (Long)
 * Long userId = Long.parseLong(identifier);
 * return userRepository.findById(userId)
 * .orElseThrow(() -> new UsernameNotFoundException("User not found"));
 * }
 * }
 * </pre>
 */
public interface AuthUserProvider {

    /**
     * Locates the user based on the unique identifier found in the Token.
     *
     * @param identifier The value extracted from JWT 'Subject' claim (Email, ID, etc.)
     * @return A fully populated user record.
     * @throws UsernameNotFoundException if the user could not be found.
     */
    UserDetails loadUserByIdentifier(String identifier) throws UsernameNotFoundException;
}