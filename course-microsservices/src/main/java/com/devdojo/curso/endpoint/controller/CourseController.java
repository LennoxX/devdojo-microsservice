package com.devdojo.curso.endpoint.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.devdojo.core.model.Course;
import com.devdojo.curso.endpoint.service.CourseService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("v1/admin/course")
@Slf4j
@Api(value = "Courses Management")
public class CourseController {

	@Autowired
	private CourseService courseService;
	
	@GetMapping
	@ApiOperation(value = "List All Courses")
	public ResponseEntity<Iterable<Course>> list(Pageable pageable) {
		return new ResponseEntity<>(courseService.list(pageable), HttpStatus.OK);
	}
	
}
