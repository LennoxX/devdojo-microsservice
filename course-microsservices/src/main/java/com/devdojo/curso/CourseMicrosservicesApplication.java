package com.devdojo.curso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.devdojo.core.property.JwtConfiguration;

@SpringBootApplication
@EntityScan({"com.devdojo.core.model"})
@EnableJpaRepositories({"com.devdojo.core.repository"})
@EnableConfigurationProperties(value = JwtConfiguration.class)
public class CourseMicrosservicesApplication {

	public static void main(String[] args) {
		SpringApplication.run(CourseMicrosservicesApplication.class, args);
	}

}
