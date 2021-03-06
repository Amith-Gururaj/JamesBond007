package amith.spring.security.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import amith.spring.security.entity.Student;

@RestController
@RequestMapping(path="/student")
public class StudentController 
{
	public static List<Student> students = Arrays.asList(
			new Student(1,"Amith.G"),
			new Student(2,"Harsh"),
			new Student(3,"Simmy")
			);
	
	
	@GetMapping(path="/{id}")
	public Student getStudent(@PathVariable("id")Integer id)
	{
		return students.stream()
				.filter(student-> id.equals(student.getId()))
				.findFirst()
				.orElseThrow(()->new IllegalStateException("Student "+ id + "does not exist"));
				
	}
}
