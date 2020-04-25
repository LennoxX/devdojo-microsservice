package com.devdojo.curso.endpoint.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.devdojo.core.model.Course;
import com.devdojo.core.repository.CourseRepository;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CourseService {

	@Autowired
	private CourseRepository courseRepository;

	public Iterable<Course> list(Pageable pageable) {

		return courseRepository.findAll(pageable);
	}
}
