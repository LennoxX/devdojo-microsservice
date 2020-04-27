package com.devdojo.token.security.filter;

import java.io.IOException;
import java.text.ParseException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.token.security.converter.TokenConverter;
import com.devdojo.token.security.util.SecurityContextUtil;
import com.nimbusds.jwt.SignedJWT;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
	protected JwtConfiguration jwtConfiguration = new JwtConfiguration();

	@Autowired
	protected TokenConverter tokenConverter = new TokenConverter();

	public JwtAuthorizationFilter(JwtConfiguration jwtConfiguration, TokenConverter tokenConverter) {
		super();
		
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(jwtConfiguration.getHeader().getName());
		if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();

		SecurityContextUtil
				.setSecurityContext(StringUtils.equalsIgnoreCase("signed", jwtConfiguration.getType()) ? validate(token)
						: decryptValidating(token));

		filterChain.doFilter(request, response);

	}

	private SignedJWT decryptValidating(String encryptedToken) {

		try {
			String signedToken = tokenConverter.decryptToken(encryptedToken);
			tokenConverter.validateTokenSignature(signedToken);
			return SignedJWT.parse(signedToken);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private SignedJWT validate(String signedToken) {

		try {
			tokenConverter.validateTokenSignature(signedToken);
			return SignedJWT.parse(signedToken);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
