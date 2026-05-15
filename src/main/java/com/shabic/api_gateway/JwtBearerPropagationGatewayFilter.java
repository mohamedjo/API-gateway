package com.shabic.api_gateway;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Ensures the downstream service receives {@code Authorization: Bearer &lt;jwt&gt;} even if the
 * header was cleared earlier in the reactive chain. Runs just before {@link org.springframework.cloud.gateway.filter.NettyRoutingFilter}.
 */
@Component
public class JwtBearerPropagationGatewayFilter implements GlobalFilter, Ordered {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return exchange.getPrincipal()
				.filter(JwtAuthenticationToken.class::isInstance)
				.cast(JwtAuthenticationToken.class)
				.map(token -> token.getToken().getTokenValue())
				.flatMap(accessToken -> {
					ServerHttpRequest mutated = exchange.getRequest().mutate()
							.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
							.build();
					return chain.filter(exchange.mutate().request(mutated).build());
				})
				.switchIfEmpty(chain.filter(exchange));
	}

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE - 1;
	}
}
