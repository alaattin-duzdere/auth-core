
# AuthCore - Spring Boot Authentication Starter

**AuthCore:** A plug-and-play Spring Boot Starter for handling JWT Authentication, OAuth2, and Security Configurations effortlessly. Eliminate boilerplate security code from your project. 

## Requirements

* **Java:** JDK 25
* **Spring Boot:** 4.0.1 or higher

## Installation

You have two options to install it:

### Option 1: Using JitPack (Recommended)
You can use **JitPack** to include this library directly from GitHub without cloning it.

**Step 1.** Add the JitPack repository to your build file:

**Maven (`pom.xml`):**
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>[https://jitpack.io](https://jitpack.io)</url>
    </repository>
</repositories>
```
**Step 2.** Add the dependency:
```xml
<dependency>
    <groupId>com.github.KULLANICI_ADIN</groupId> <artifactId>auth-core-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Option 2: Local Installation (Clone & Build)
If you prefer to run it locally, follow these steps:

**1. Clone the repository:**
```bash
git clone https://github.com/alaattin-duzdere/auth-core
```

**2. Install to local Maven repository:** Navigate to the project folder and run:
```bash 
mvn clean install
```

**3. Add dependency to your project:** Now you can use the dependency in your project's
```xml
<dependency>
    <groupId>com.authcore</groupId>
    <artifactId>auth-core-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```



## Configuration

Add the following properties on your application.properties or application.yml file

**application.yml:**
```yml
auth-core:
  secret-key: "YOUR_SECRET_BASE64_KEY_HERE"
  expiration-ms: 86400000 
  enable-oauth: false     
  whitelist:
    - "/auth/**"
    - "/public/**"
    - "/swagger-ui/**"
    - "/v3/api-docs/**"
```
**application.properties**
```properties
auth-core.secret-key=YOUR_SUPER_SECRET_BASE64_KEY_HERE
auth-core.expiration-ms=86400000
auth-core.enable-oauth=false
# Note: Use array index notation [0], [1]...
auth-core.whitelist[0]=/auth/**
auth-core.whitelist[1]=/public/**
auth-core.whitelist[2]=/swagger-ui/**
auth-core.whitelist[3]=/v3/api-docs/**
```
    
## Usage

**1. Implement User Provider:** 

You need to tell AuthCore how to fetch users from your database. Implement the AuthUserProvider interface in your Service layer:
```java 
@Service
@RequiredArgsConstructor
public class SecurityUserService implements AuthUserProvider {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByIdentifier(String identifier) {
        // 'identifier' can be email, username, or ID based on your logic
        return userRepository.findByEmail(identifier)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + identifier));
    }
}
```

**2. Create Auth Endpoints:**

Inject AuthenticationManager and JwtService (provided by AuthCore) into your controller. 

**Example:** 
```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        // 1. Authenticate (Checks password, account status, etc.)
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        
        // 2. Retrieve User
        UserDetails user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        
        // 3. Generate Token
        String token = jwtService.generateToken(user);
        
        return ResponseEntity.ok(token);
    }
}
```


## 🧩 Customization & Bean Overriding

AuthCore is flexible. It uses Spring's `@ConditionalOnMissingBean` annotation internally. This means you can override the default behavior simply by defining your own beans in your application context.

### Example: Changing Password Encoder
By default, AuthCore uses **BCrypt**. If you prefer a different algorithm (e.g., Argon2 or SCrypt), just define a `PasswordEncoder` bean in your project configuration. AuthCore will automatically back off and use yours.

```java
@Configuration
public class MySecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Example: Using Argon2 instead of default BCrypt
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
    }
}
