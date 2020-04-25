package com.devdojo.core.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import com.devdojo.core.model.Course;


public interface CourseRepository extends PagingAndSortingRepository<Course, Long>{
	

}
