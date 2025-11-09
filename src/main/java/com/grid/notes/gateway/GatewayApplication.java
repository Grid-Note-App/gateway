package com.grid.notes.gateway;

import lombok.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder,
                                           @Value("${env.url.frontend}") String frontendUrl,
                                           @Value("${env.url.notes-service}") String notesServiceUrl,
                                           @Value("${env.url.chat-service}") String chatServiceUrl) {
        return builder.routes()
            .route("chat-service", r -> r
                .order(0)
                .path("/api/ai/**")
                .filters(f -> f.rewritePath("/api/ai/(?<segment>.*)", "/${segment}"))
                .uri(chatServiceUrl)
            )
            .route("notes-service", r -> r
                .order(10)
                .path("/api/**")
                .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/${segment}"))
                .uri(notesServiceUrl)
            )
            .route("frontend", r -> r
                .order(100)
                .path("/**")
                .uri(frontendUrl)
            )
            .build();
    }

}

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
class UserController {

    private final UserEntityRepository userRepository;

    @Builder
    record UserResponse(
        String id,
        String externalId,
        String firstName,
        String lastName,
        String email,
        String pictureUrl,
        String idToken
    ) {

    }

    @GetMapping("currentUser")
    Mono<UserResponse> getCurrentUser(@AuthenticationPrincipal OidcUser principal) {
        if (principal == null) {
            return Mono.empty();
        }
        String externalId = principal.getSubject();
        return userRepository.findByExternalId(externalId)
            .map(entity -> UserResponse.builder()
                .id(entity.getId())
                .externalId(externalId)
                .firstName(entity.getFirstName())
                .lastName(entity.getLastName())
                .email(entity.getEmail())
                .pictureUrl(entity.getPictureUrl())
                .idToken(principal.getIdToken().getTokenValue())
                .build()
            );
    }
}


@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
            .oauth2Login(Customizer.withDefaults())
            .oauth2Client(Customizer.withDefaults())
            .build();
    }
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("user_entity")
class UserEntity {

    @Id
    private String id;
    private String externalId;
    private String firstName;
    private String lastName;
    private String email;
    private String pictureUrl;

}

interface UserEntityRepository extends ReactiveMongoRepository<UserEntity, String> {

    Mono<UserEntity> findByExternalId(String externalId);

}

@Component
@RequiredArgsConstructor
class DownstreamTokenRelayFilter implements GlobalFilter {

    private final ServerOAuth2AuthorizedClientRepository clientRepository;
    private final UserEntityRepository userRepository;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
            .flatMap(ctx -> {
                Authentication auth = ctx.getAuthentication();
                if (!(auth instanceof OAuth2AuthenticationToken oauth2Auth)) {
                    return chain.filter(exchange);
                }

                return clientRepository
                    .loadAuthorizedClient(oauth2Auth.getAuthorizedClientRegistrationId(), auth, exchange)
                    .flatMap(client -> {
                        OidcUser principal = (OidcUser) oauth2Auth.getPrincipal();
                        String idToken = principal.getIdToken().getTokenValue();
                        return createOrUpdateUser(principal)
                            .then(Mono.defer(() -> {
                                ServerHttpRequest mutated = exchange.getRequest().mutate()
                                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + idToken)
                                    .build();

                                return chain.filter(exchange.mutate().request(mutated).build());
                            }));
                    });
            });
    }

    private Mono<UserEntity> createOrUpdateUser(OidcUser principal) {
        String externalId = principal.getSubject();
        String email = principal.getEmail();

        String firstName = principal.getGivenName();
        String lastName = principal.getFamilyName();
        String picture = principal.getPicture();

        return userRepository.findByExternalId(externalId)
            .flatMap(existing -> {
                existing.setEmail(email);
                existing.setFirstName(firstName);
                existing.setLastName(lastName);
                existing.setPictureUrl(picture);
                return userRepository.save(existing);
            })
            .switchIfEmpty(
                userRepository.save(UserEntity.builder()
                    .externalId(externalId)
                    .email(email)
                    .firstName(firstName)
                    .lastName(lastName)
                    .pictureUrl(picture)
                    .build())
            );
    }
}
