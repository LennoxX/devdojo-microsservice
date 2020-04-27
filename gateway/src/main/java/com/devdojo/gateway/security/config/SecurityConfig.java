package com.devdojo.gateway.security.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.gateway.security.filter.GatewayJWTAuthorizationFilter;
import com.devdojo.token.security.config.SecurityTokenConfig;
import com.devdojo.token.security.converter.TokenConverter;

@EnableWebSecurity
@EnableZuulProxy
@EnableEurekaClient
@EnableConfigurationProperties(value = JwtConfiguration.class)
public class SecurityConfig extends SecurityTokenConfig {

	private TokenConverter tokenConverter = new TokenConverter();

	public SecurityConfig(JwtConfiguration jwtConfiguration) {
		super(jwtConfiguration);

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAfter(new GatewayJWTAuthorizationFilter(jwtConfiguration, tokenConverter),
				UsernamePasswordAuthenticationFilter.class);
		super.configure(http);

	}

}
