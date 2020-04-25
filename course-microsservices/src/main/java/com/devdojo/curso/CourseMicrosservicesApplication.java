package com.devdojo.curso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"com.devdojo.core.model"})
@EnableJpaRepositories({"com.devdojo.core.repository"})
public class CourseMicrosservicesApplication {

	public static void main(String[] args) {
		SpringApplication.run(CourseMicrosservicesApplication.class, args);
	}

}
