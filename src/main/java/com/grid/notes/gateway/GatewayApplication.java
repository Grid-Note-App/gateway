package com.grid.notes.gateway;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
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
                                           @Value("${env.url.notes-service}") String notesServiceUrl) {
        return builder.routes()
            .route("notes-service", r -> r
                .order(0)
                .path("/api/**")
                .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/${segment}"))
                .uri(notesServiceUrl)
            )
            .route("frontend", r -> r
                .order(10)
                .path("/**")
                .uri(frontendUrl)
            )
            .build();
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

@Component
@RequiredArgsConstructor
class DownstreamTokenRelayFilter implements GlobalFilter {

    private final ServerOAuth2AuthorizedClientRepository clientRepository;

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

                        ServerHttpRequest mutated = exchange.getRequest().mutate()
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + idToken)
                            .build();

                        return chain.filter(exchange.mutate().request(mutated).build());
                    });
            });
    }
}
