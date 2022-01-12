package com.apress.todo.todosimplesecurity.repository;


import com.apress.todo.todosimplesecurity.domain.ToDo;
import org.springframework.data.repository.CrudRepository;

public interface ToDoRepository extends CrudRepository<ToDo, String> {

}
