package com.devdojo.token.security.util;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.devdojo.core.model.ApplicationUser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SecurityContextUtil {

	private SecurityContextUtil() {

	}

	public static void setSecurityContext(SignedJWT signedJWT) {
		try {
			JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
			String username = claimsSet.getSubject();
			if (username == null)
				throw new JOSEException("Username missing from JWT!");
			List<String> authorities = claimsSet.getStringListClaim("authorities");
			ApplicationUser applicationUser = new ApplicationUser();
			applicationUser.setId(claimsSet.getLongClaim("userId"));
			applicationUser.setUsername(username);
			applicationUser.setRole(String.join(",", authorities));
			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(applicationUser, null,
					createAuthorities(authorities));
			auth.setDetails(signedJWT.serialize());
			SecurityContextHolder.getContext().setAuthentication(auth);
		} catch (Exception e) {
			e.printStackTrace();
			SecurityContextHolder.clearContext();
		}
	}

	private static List<SimpleGrantedAuthority> createAuthorities(List<String> authorities) {
		return authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}
}
