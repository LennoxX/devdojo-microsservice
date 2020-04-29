package com.devdojo.curso.docs;

import org.springframework.context.annotation.Configuration;

import com.devdojo.core.docs.BaseSwaggerConfig;

import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {

	public SwaggerConfig() {
	super("com.devdojo.curso.endpoint.controller");
	}
}
