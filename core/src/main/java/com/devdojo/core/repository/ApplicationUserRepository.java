package com.devdojo.core.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import com.devdojo.core.model.ApplicationUser;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

	ApplicationUser findByUsername(String username);

}
