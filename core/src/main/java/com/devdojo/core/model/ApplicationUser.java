package com.devdojo.core.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Entity
@Builder
@ToString(exclude = "password")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class ApplicationUser {

	public ApplicationUser() {

	}

	public ApplicationUser(Long id, @NotNull(message = "Campo 'username' Obrigatório") String username,
			@NotNull(message = "Campo 'password' Obrigatório") String password,
			@NotNull(message = "Campo 'role' Obrigatório") String role) {
		super();
		this.id = id;
		this.username = username;
		this.password = password;
		this.role = role;
	}

	public ApplicationUser(ApplicationUser applicationUser) {
		this.id = applicationUser.getId();
		this.username = applicationUser.getUsername();
		this.password = applicationUser.getPassword();
		this.role = applicationUser.getRole();
	}

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@EqualsAndHashCode.Include
	private Long id;

	@NotNull(message = "Campo 'username' Obrigatório")
	@Column(nullable = false)
	private String username;

	@NotNull(message = "Campo 'password' Obrigatório")
	@Column(nullable = false)
	private String password;

	@NotNull(message = "Campo 'role' Obrigatório")
	@Column(nullable = false)
	private String role = "USER";

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

}
