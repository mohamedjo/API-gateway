package com.shabic.api_gateway;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			ObjectProvider<ReactiveJwtDecoder> reactiveJwtDecoder) {
		http.csrf(ServerHttpSecurity.CsrfSpec::disable);
		http.cors(Customizer.withDefaults());

		ReactiveJwtDecoder decoder = reactiveJwtDecoder.getIfAvailable();
		if (decoder != null) {
			http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		}

		http.authorizeExchange(exchanges -> {
			exchanges.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();
			exchanges.pathMatchers("/actuator/health", "/actuator/info").permitAll();
			if (decoder != null) {
				exchanges.anyExchange().authenticated();
			} else {
				exchanges.anyExchange().permitAll();
			}
		});

		return http.build();
	}
}
