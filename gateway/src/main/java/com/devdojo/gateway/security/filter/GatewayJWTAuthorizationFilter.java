package com.devdojo.gateway.security.filter;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.token.security.converter.TokenConverter;
import com.devdojo.token.security.filter.JwtAuthorizationFilter;
import com.devdojo.token.security.util.SecurityContextUtil;
import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;

public class GatewayJWTAuthorizationFilter extends JwtAuthorizationFilter {

	public GatewayJWTAuthorizationFilter(JwtConfiguration jwtConfiguration, TokenConverter tokenConverter) {
		super(jwtConfiguration, tokenConverter);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		/*
		 * List<String> list = new ArrayList<String>();
		 * request.getHeaderNames().asIterator().forEachRemaining(list::add); for
		 * (String name : list) System.out.println(name);
		 */
		String header = request.getHeader(jwtConfiguration.getHeader().getName());

		if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();

		String signedToken = tokenConverter.decryptToken(token);

		tokenConverter.validateTokenSignature(signedToken);

		try {
			SecurityContextUtil.setSecurityContext(SignedJWT.parse(signedToken));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (jwtConfiguration.getType().equalsIgnoreCase("signed"))
			RequestContext.getCurrentContext().addZuulRequestHeader("Authorization",
					jwtConfiguration.getHeader().getPrefix() + signedToken);

		filterChain.doFilter(request, response);

	}

}
